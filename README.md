###1. Explain basic security terms like authentication, authorization, confidentiality, integrity, SSL/TLS and provide examples of how you have used them. 

####Authentication
In contrast with identification which refers to the act of stating or otherwise indicating a claim purportedly attesting to a person or thing's identity, authentication is the process of actually confirming that identity. In computer science, verifying a person's identity is often required to allow access to confidential data or systems.

####Authorization
Is the function of specifying access rights to resources related to information security and computer security in general and to access control in particular. More formally, "to authorize" is to define an access policy. For example, human resources staff is normally authorized to access employee records and this policy is usually formalized as access control rules in a computer system. 
Confidentiality**: Involves a set of rules or a promise that limits access or places restrictions on certain types of information. In information security, confidentiality "is the property, that information is not made available or disclosed to unauthorized individuals, entities, or processes".

####Integrity
Maintaining and assuring the accuracy and completeness of data over its entire life-cycle. This means that data cannot be modified in an unauthorized or undetected manner.

####SSL/TLS
The Secure Socket Layer, SSL for short, is a protocol by which enables services that communicate over the Internet to do so securely. SSL has recently been replaced by TLS (Transport Layer Security). TLS is newer and more secure than SSL; however, from a lay-person’s perspective of “how does it work,” they are functionally the same. **Provide github example here!**

*sources* <br>
[Wikipedia - Authentication](https://en.wikipedia.org/wiki/Authentication) <br>
[Wikipedia - Authorization](https://en.wikipedia.org/wiki/Authorization) <br>
[wikipedia - Confidentiality](https://en.wikipedia.org/wiki/Confidentiality) <br>
[Wikipedia - Information Security (confidentiality + integrity) ](https://en.wikipedia.org/wiki/Information_security) <br>
[MEAN slides - Security 1 - SSL](http://js2016.azurewebsites.net/security1/security.html#16) <br>
[LuxSci FYI Blog - SSL/TLS](https://luxsci.com/blog/how-does-secure-socket-layer-ssl-or-tls-work.html)


###2. Explain basic security threads like: Cross Site Scripting (XSS), SQL Injection and whether something similar to SQL injection is possible with NoSQL databases like MongoDB, and DOS-attacks. Explain/demonstrate ways to cope with these problems 

####XSS
Attackers fold malicious content into the content being delivered from the compromised site. When the resulting combined content arrives at the client-side web browser, it has all been delivered from the trusted source, and thus operates under the permissions granted to that system. By finding ways of injecting malicious scripts into web pages, an attacker can gain elevated access-privileges to sensitive page content, to session cookies, and to a variety of other information maintained by the browser on behalf of the user. <br>
Ex in steps -> <br>
1) Alice logs into Bob's website and gets back an authorization cookie. Bob website saves Alice's billing information.<br>
2) Mallory uses Bob's search page to inject a script into the search query, 
ex. `<script type='text/javascript'>alert('xss');</script>` <br>
3) Mallory sends an email to Alice containing the "abnormal" search query. Alice clicks the link and the malicious script is run.<br>
4) The script grabs a copy of Alice's Authorization Cookie and sends it to Mallory's server.<br>
5) Mallory logs into the site as Alice, using the Authorization Cookie.<br>
6) The fun begins, as Mallory steals Alice's credit card info, changes her password and so on.
 
####SQL Injection
A code injection technique, used to attack data-driven applications, in which malicious SQL statements are inserted into an entry field for execution (e.g. to dump the database contents to the attacker). SQL injection attacks allow attackers to spoof identity, tamper with existing data, cause repudiation issues such as voiding transactions or changing balances, allow the complete disclosure of all data on the system, destroy the data or make it otherwise unavailable, and become administrators of the database server.<br>
ex. in steps -> <br><br>
1) Server gets text directly from input field:<br> 
``` sql txtUserId = getRequestString("UserId"); ``` <br>
`txtSQL = "SELECT * FROM Users WHERE UserId = " + txtUserId;` <br><br>
2) User inputs following code into inputfield: *"105 or 1=1"* <br>
sql query then becomes: 
```SELECT UserId, Name, Password FROM Users WHERE UserId = 105 or 1=1``` which returns all rows from table 'Users'.<br><br>
More examples on [w3schools](http://www.w3schools.com/sql/sql_injection.asp). 

####NoSQL Injection
We no longer deal with a query language in the form of a string therefore one would think that injection is no longer possible... wrong! For example, assume that the username field is coming from a deserialized JSON object, manipulation of the above query is not only possible but inevitable. Such as, if one supplies a JSON document as the input to the application, an attacker will be able to perform the exact same login bypass that was before possible only with SQL injection.<br>
**Ex. MongoDB Injection**:<br>
Server code: 
```db.accounts.find({username: username, password: password});```<br>
Client creates following json request -> <br>
```{
    "username": "admin",
    "password": {$gt: ""}
}``` <br><br>
Result is that "Get all users with username admin and password greater than emptry String", returns all admins.

####DoS-attack
A denial-of-service attack is characterized by an explicit attempt by attackers to prevent legitimate users of a service from using that service. There are two general forms of DoS attacks: those that crash services and those that flood services.
The most serious attacks are distributed (DDoS) and in many or most cases involve forging of IP sender addresses (IP address spoofing) so that the location of the attacking machines cannot easily be identified, nor can filtering be done based on the source address.

**DoS-attack on MongoDB**: If you have a large table with an index on _id and you do a query like BlogPost.find(params[:id]), an attacker can craft a query that forces MongoDB to do a full table scan.

####Coping with these problems: 
- (SQL) Use prepared statements instead of building dynamic queries with string concatenation.
- (SQL & NoSQL) Validate input.
- (SQL & NoSQL) Do not admin type access rights to users.
- Sanitize: Filter all user input. Ideally, user data should be filtered for context. For example, e-mail addresses should be filtered to allow only the characters allowed in an e-mail address, phone numbers should be filtered to allow only the characters allowed in a phone number, and so on. **Provide github example here!**

*sources* <br>
[Wikipedia - Cross Side Scripting (XSS)](https://en.wikipedia.org/wiki/Cross-site_scripting)<br>
[Wikipedia - SQL Injection](https://en.wikipedia.org/wiki/SQL_injection)<br>
[w3schools SQL Injection](http://www.w3schools.com/sql/sql_injection.asp)<br>
[blog.websecurify - SQL & NoSQL examples](http://blog.websecurify.com/2014/08/hacking-nodejs-and-mongodb.html)
[OWASP NodeGoat Tutorial](https://ckarande.gitbooks.io/owasp-nodegoat-tutorial/content/tutorial/a1_-_sql_and_nosql_injection.html) <-- cool site with several security-issue examples!<br>
[Wikipedia - DOS-attack](https://en.wikipedia.org/wiki/Denial-of-service_attack)<br>
[MongoDB hash-injection attacks](https://cirw.in/blog/hash-injection)<br>
[Sanitize](http://www.esecurityplanet.com/hackers/how-to-prevent-sql-injection-attacks.html)<br>

###3. Explain, at a fundamental level, the technologies involved, and the steps required to initialize a SSL connection between a browser and a server and how to use SSL in a secure way. 

![Overview of the SSL/TLS handshake](http://i.imgur.com/XO5JVIt.png) <br>
source: [http://www.ibm.com/support/knowledgecenter/SSFKSJ_7.1.0/com.ibm.mq.doc/sy10660_.htm?lang=en](http://www.ibm.com/support/knowledgecenter/SSFKSJ_7.1.0/com.ibm.mq.doc/sy10660_.htm?lang=en)

1) The client sends a "client hello" message that lists cryptographic information such as the SSL/TLS version, a random byte string that is used in subsequent computations etc. 

2) The server responds with a "server hello" message that contains the CipherSuite chosen by the server from the list provided by the client, the session ID, and another random byte string. Also a digital certificate. 

3) The client verifies the server's digital certificate. 

4) The client sends the random byte string that enables both the client and the server to compute the secret key to be used for encrypting subsequent message data. The random byte string itself is encrypted with the server's public key.

5) If the server sent a "client certificate request", the client sends a random byte string encrypted with the client's private key, together with the client's digital certificate, or a "no digital certificate alert". This alert is only a warning, but with some implementations the handshake fails if client authentication is mandatory. 
**OPTIONAL step?**

6) The server verifies the client's certificate. 

7) The client sends the server a "finished" message, which is encrypted with the secret key, indicating that the client part of the handshake is complete.

8) The server sends the client a "finished" message, which is encrypted with the secret key, indicating that the server part of the handshake is complete.

9) For the duration of the session, the server and client can now exchange messages that are symmetrically encrypted with the shared secret key.

###4. Explain and demonstrate ways to protect user passwords on our backends, and why this is necessary. 

Refer to answer for question 5).

###5. Explain about password hashing, salts and the difference between bcrypt and older (not recommended) algorithms like sha1, md5 etc.

####Hashing 

Hash algorithms are **one way functions**. They turn any amount of data into a fixed-length "fingerprint" that cannot be reversed. They also have the property that if the input changes by even a tiny bit, the resulting hash is completely different.<br>
Ex. <br>
```hash("hello") = 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824```<br>
```hash("hbllo") = 58756879c05c68dfac9866712fad6a93f8146f337a69afe7dd238f3364946366```<br>

**Typical workflow for account creation:** user creates account -> password is hashed and stored in db -> at login entered password is hashed and checked against the hashed password in db.<br>

####Salting

Randomize the hashes by appending or prepending a random string, called a salt, to the password before hashing. This makes the same password hash into a completely different string every time. To check if a password is correct, we need the salt, so it is usually stored in the user account database along with the hash, or as part of the hash string itself.

```hash("hello")                    = 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824```<br>
```hash("hello" + "QxLUF1bgIAdeQX") = 9e209040c863f84a31e719795b2577523954739fe5ed3b58a75cff2127075ed1```

The salt needs to be unique per-user per-password. Every time a user creates an account or changes their password, the password should be hashed using a new random salt. Never reuse a salt. The salt also needs to be long, so that there are many possible salts. As a rule of thumb, make your salt is at least as long as the hash function's output. The salt should be stored in the user account table alongside the hash.

####sha1, md5 (message-digest algorithms)
The **MD5** message-digest algorithm is a widely used cryptographic hash function producing a **128-bit** (16-byte) hash value, typically expressed in text format as a 32-digit hexadecimal number. MD5 has been utilized in a wide variety of cryptographic applications and is also commonly used to verify data integrity.

```MD5("The quick brown fox jumps over the lazy dog") =```<br>
```9e107d9d372bb6826bd81d3542a419d6```

In cryptography, **SHA-1** (Secure Hash Algorithm 1) is a cryptographic hash function designed by the United States National Security Agency and is a U.S. Federal Information Processing Standard published by the United States NIST.[2] SHA-1 produces a **160-bit** (20-byte) hash value known as a message digest. A SHA-1 hash value is typically rendered as a hexadecimal number, 40 digits long.<br>

**SHA1("The quick brown fox jumps over the lazy dog")<br>
gives hexadecimal: 2fd4e1c67a2d28fced849ee1bb76e7391b93eb12<br>
gives Base64 binary to ASCII text encoding: L9ThxnotKPzthJ7hu3bnORuT6xI=1<br>**

####bcrypt

bcrypt is a key derivation function for passwords, based on the Blowfish cipher. Besides incorporating a salt to protect against rainbow table attacks, bcrypt is an adaptive function: over time, the iteration count can be increased to make it slower, so it remains resistant to brute-force search attacks even with increasing computation power. <br>
Ex. Implementation here: [Github - NodeServerSeed](https://github.com/hardboilr/NodeServerSeed/blob/master/models/user.js). Passwords are hashed and salted before being saved to db.

[Wikipedia - MD5]()<br>
[Wikipedia - SHA-1](https://en.wikipedia.org/wiki/SHA-1) <br>
[yorickpeterse.com - bcrypt](http://yorickpeterse.com/articles/use-bcrypt-fool/) <br>
[crackstation.net - Password hashing](https://crackstation.net/hashing-security.htm) <br>
[Wikipedia - bcrypt](https://en.wikipedia.org/wiki/Bcrypt)

###6. Explain about JSON Web Tokens (jwt) and why they are very suited for a REST-based API

In authentication, when the user successfully logs in using his credentials, a JSON Web Token will be returned and must be saved locally (typically in local storage, but cookies can be also used). <br>
Whenever the user wants to access a protected route or resource, the user agent should send the JWT, typically in the Authorization header using the Bearer schema. The content of the header could look like the following: `Authorization: <token>`<br>
This is a stateless authentication mechanism as the user state is never saved in server memory. The server's protected routes will check for a valid JWT in the Authorization header, and if it's present, the user will be allowed to access protected resources. This allows you to fully rely on data APIs that are **stateless** and even make requests to downstream services.

[JSON Web Tokens](https://jwt.io/introduction/)

###7. Explain and demonstrate a system using jwt's, focusing on both client and server side. 

####Server

Refer to [Github project - NodeServerSeed](https://github.com/hardboilr/NodeServerSeed)

**app.js ->** For all request to endpoint /api, the server will run "passport.authenticate" to authenticate the user.

```javascript
app.use('/api', function (req, res, next) {
    passport.authenticate('jwt', {session: false}, function (err, user, info) {
        if (err) {
            res.status(403).json({mesage: "Token could not be authenticated", fullError: err})
        }
        if (user) {
            return next();
        }
        return res.status(403).json({mesage: "Token could not be authenticated", fullError: info});
    })(req, res, next);
});
```

**config/passport.js ->** Checks incoming jwt from client against jwtConfig. Also checks that user exists in db. 

```javascript
module.exports = function (passport) {

    var opts = {};
    opts.secretOrKey = jwtConfig.secret;
    opts.issuer = jwtConfig.issuer;
    opts.audience = jwtConfig.audience;
    opts.jwtFromRequest = ExtractJwt.fromAuthHeader();
    // opts.jwtFromRequest = ExtractJwt.fromAuthHeaderWithScheme("Bearer");
    passport.use(new JwtStrategy(opts, function (jwt_payload, done) {
        console.log("PAYLOAD: " + jwt_payload);
        User.findOne({username: jwt_payload.sub}, function (err, user) {
            if (err) {
                return done(err, false);
            }
            if (user) {
                done(null, user); //You could choose to return the payLoad instead
            }
            else {
                done(null, false, "User found in token not found");
            }
        })
    }))
};
```
####Client

Refer to [Github project - AngularClientSeed](https://github.com/hardboilr/NodeServerSeed)

**app.js ->** when submit() is invoked, then save token from server in a session (`$window.sessionStorage.token = data.token;`). 

The factory "authInterceptor" will intercept every outgoing http request and add an authorization header with the saved token (`config.headers.Authorization = $window.sessionStorage.token;`).

###8. Explain and demonstrate use of the npm passportjs module

To be announced... 

###9. Explain, at a very basic level, OAuth 2 + OpenID Connect and the problems it solves. 

To be announced... 

###10. Demonstrate, with focus on security, a proposal for an Express/Mongo+Angular-seed with built in support for most of the basic security problems, SSL and ready to deploy on your favourite Cloud Hosting Service. 

To be announced... 