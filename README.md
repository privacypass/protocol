# Extended protocol design

The protocol that is implemented in Privacy Pass is built upon elliptic-curve cryptography, specifically using the NIST P-256 curve. We can think of our protocol as a variant of a 'blind signature scheme'. 

The concept of a blind signature has been around since David Chaum introduced [RSA blinding](https://dl.acm.org/citation.cfm?doid=4372.4373) in 1985. Our system is conceptually similar to Chaum’s original idea: it lets someone with a private key digitally sign a message without knowing what it is, but rather than an RSA private key, an Elliptic Curve private key is used. The construction we use was developed independently, but bears resemblance to recent [EC-OPRF](https://eprint.iacr.org/2017/111) and [EC-VRF](https://tools.ietf.org/html/draft-goldbe-vrf-01) proposals. The Privacy Pass team developed this scheme with the help of experts in cryptography such as Dan Boneh.

To make the design decisions behind the development of the Privacy Pass protocol clear, we detail a set of scenarios each with flaws. In each scenario we address a flaw of the previous construction and show how to avoid it. By Scenario 7 we have something very close to our scheme. In these scenarios there are two actors, the client and the server.

Additionally, see the [full description](https://github.com/privacypass/challenge-bypass-extension/blob/master/PROTOCOL.md) for more details.

## Scenario 1

The client takes a point on an elliptic curve `T` and sends it to the server. The server applies a secret transformation (multiplication by a secret number `s`) and sends it back. Call this step “Issue”, as the server issues a signed point to the client.

#### Issue
	T -> 
    	<-  sT

Later, the client sends `T` and `sT` to the server to prove it has previously issued `sT`.

#### Redeem
	T, sT -> 

Since only the server knows `s`, it can confirm that it had issued `sT`. We call this step “Redeem”.

#### Problem: Linkability

In this situation, the server knows `T` because it has seen it already. This lets the server connect the two requests, something we’re trying to avoid. This is where we introduce the blinding factor.


## Scenario 2

Rather than sending `T`, the client generates its own secret number `b`. The client multiplies the point `T` by `b` before sending it to the server. The server does the same thing as in scenario 1 (multiplies the point it receives by `s`).

#### Issue
	bT ->
      	<- s(bT)

The client knows `b` and `s(bT)` is equal to `b(sT)` because multiplication is commutative. The client can compute `sT` from `b(sT)` by dividing by `b`. To redeem, the client sends `T`, `sT`. 

#### Redeem
	T, sT ->

Since only the server knows `s`, it can confirm that `sT` is `T` multiplied by `s` and will verify the redemption.

#### Problem: Malleability
It’s possible to create an arbitrary number of pairs of points that will be verified. The client can create these points by multiplying both `T` and `sT` by an arbitrary number `a`. If the client attempts to redeem `aT` and `a(sT)`, the server will accept it. This effectively gives the client unlimited redemptions.

## Scenario 3

Instead of picking an arbitrary point `T`, the client can pick a number `t`. The point `T` can be derived by hashing `t` to a point on the curve using a one-way hash. The hash guarantees that it’s hard to find another number that hashes to `aT` for an arbitrary a.

#### Issue
	T = Hash(t) 
	bT ->
    	  <- sbT

#### Redeem
	t, sT ->

Since only the server knows s, it can compute `T = Hash(t)` and confirm that `sT` is `T` multiplied by `s` and will verify the redemption.

#### Problem: Redemption hijacking
If the values `t` and `sT` are sent across an unsecured network, an adversary could take them and use them for their own redemption.

Sending `sT` is what lets attackers hijack a redemption. Since the server can calculate `sT` from `t` on it’s own, the client doesn’t actually need to send it. All the client needs to do is prove that it knows `sT`. A trick for doing this is to use `t` and `sT` to derive a HMAC key and use it to sign a message that relates to the redemption. Without seeing `sT`, the attacker will not be able to take this redemption and use it for a different message because it won’t be able to compute the HMAC key.

## Scenario 4

Instead of sending `t` and `sT` the client can send `t` and `HMAC(sT, M)` for a message `M`. When the server receives this, it calculates `T = Hash(t)`, then uses its secret value to compute `sT`. With `t` and `sT` it can generate the HMAC key and check the signature. If the signature matches, that means the client knew `sT`.

#### Issue
	T = Hash(t) 
	bT ->
    	  <- sbT

#### Redeem
	t, HMAC(sT, M) ->

Since only the server knows s, it can compute `T = Hash(t)` and compute `sT` as `T` multiplied by `s` and verify the HMAC to validate that the client knew `sT`.

#### Problem: Tagging
The server can use a different s for each client, say `s_1` for client 1 and `s_2` for client 2. Then the server can identify the client by comparing `s_1*Hash(t)` and `s_2*Hash(t)` against the `sT` submitted by the client and seeing which one matches.

This is where we introduce a zero-knowledge proof. We’ll go into more detail about how these work in a later blog post. The specific proof we’re using is called a discrete logarithm equivalence proof (DLEQ).

Those lucky enough to take the SAT before 2005 may remember the [analogy section](https://blog.prepscholar.com/sat-analogies-and-comparisons-why-removed-what-replaced-them). You can think of a DLEQ proof in terms of an SAT analogy. It proves that two pairs of items are related to each other in a similar way.

For example: puppies are to dogs as kittens are to cats. A kitten is a young cat and a puppy is a young dog. You can represent this with the following notation:
puppy:dog == kitten:cat

A DLEQ proves that two elliptic curve points are related by the same multiplicative factor without revealing that factor. Say you have a number `s` and two points `P` and `Q`. Someone with knowledge of s can construct a proof `DLEQ(P:sP == Q:sQ)`. A third party with access to `P`, `sP`, `Q`, `sQ` can use `DLEQ(P:sP == Q:sQ)` to verify that the same value s was used without knowing what s is. 

## Scenario 5

The server picks a generator point `G` and publishes `sG` somewhere where every client knows it.

#### Issue
	T = Hash(t) 
	bT ->
    	  <- sbT, DLEQ(bT:sbT == G:sG)

The client can then check to see that the server used the same `s`, since everyone knows `sG`.

#### Redeem
	t, HMAC(sT, M) ->

Just like in Scenario 4, since only the server knows s, it can compute `T = Hash(t)` and compute `sT` as `T` multiplied by `s` and verify the HMAC to validate that the client knew `sT`.

#### Problem: only one redemption per issuance
This system seems to have all the properties we want, but it would be nice to be able to get multiple points.

## Scenario 6

The client picks multiple values `t1, t2, … , tn` and multiple blinding factors `b1, b2, … , bn`. For simplicity, let’s make n=3, but it could be an arbitrary number.

#### Issue
	T1 = Hash(t1) 
	T2 = Hash(t2)
	T3 = Hash(t3)
	b1T1 ->
	b2T2 ->
	b3T3 ->
			<- sbT1, DLEQ(b1T1:sbT1 == G: sG)
			<- sbT2, DLEQ(b2T2:sbT2 == G: sG)
			<- sbT3, DLEQ(b3T3:sbT3 == G: sG)

Each DLEQ can be verified independently like in Scenario 4, the client is safe from tagging.

#### Redeem
	t1, HMAC1(M) ->

This lets the client do multiple redemptions.

#### Problem: Bandwidth
DLEQ proofs are not particularly compact. Luckily, they can be optimized with something called an efficient batch DLEQ proof. It’s essentially a single proof that covers all the returned values. This can be done by computing a proof over a random linear combination of the points:

Because the same `s` is used for every `T`, you can use the commutative property of multiplication again to help you.

Note the following:
	
	sb1T1+sb2T2+sb3T3 = s(b1T1+b2T2+b3T3)

So the server can compute a single DLEQ that proves that the same s was used for each T:
`DLEQ(b1T1+b2T2+b3T3:s(b1T1+b2T2+b3T3) == G: sG)`
This is the same size as a single DLEQ proof. 

In fact, as mentioned above, we take a random linear combination of these points without compromising the malleability requirement. In particular, we seed a Pseudorandom Number Generator (PRNG) using the output `z` of a hash computation over the common information in the signing phase (e.g. blinded/signed points). We then parse the output of `PRNG(z)` to be `c1,c2,c3`. We can then compute:
	
	DLEQ(c1b1T1+c2b2T2+c3b3T3:s(c1b1T1 + c2b2T2 + c3b3T3) == G: sG)

Without using the random linear combinations the proof is insecure. 

## Scenario 7

This scenario is similar to the last one except that the server sends a batch DLEQ proof rather than one for each point.

#### Issue
	T1 = Hash(t1) 
	T2 = Hash(t2)
	T3 = Hash(t3)
	b1T1 ->
	b2T2 ->
	b3T3 ->
			c1,c2,c3 = H(G,sG,b1T1,b2T2,b3T3,s(b1T1),s(b2T2),s(b3T3))
			<- sb1T1
			<- sb2T2
			<- sb3T3
			<- DLEQ(c1b1T1+c2b2T2+c3b3T3:s(c1b1T1+c2b2T2+c3b3T3) == G: sG)

This DLEQ proof can be validated by recomputing `z = c1,c2,c3` and then `c1b1T1+c2b2T2+c3b3T3` and `sc1b1T1+sc2b2T2+sc3b3T3`.

#### Redeem
	t1, HMAC1(M) ->

This is basically our scheme.

## The scheme in detail

We have published a detailed [specification](https://github.com/privacypass/challenge-bypass-extension/blob/master/PROTOCOL.md) of our scheme if you are interested in learning more. We also address some more possible attack avenues with working mitigations that are in use currently with respect to the Cloudflare implementation.
