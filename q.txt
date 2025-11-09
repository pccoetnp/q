
Q8 : 

#include <iostream>
#include <fstream>
using namespace std;

int main() {
    string filename, outname;
    char key;

    cout << "Enter image filename to encrypt/decrypt: ";
    cin >> filename;
    cout << "Enter output filename: ";
    cin >> outname;
    cout << "Enter single character key: ";
    cin >> key;

    ifstream input(filename, ios::binary);
    ofstream output(outname, ios::binary);

    if (!input || !output) {
        cout << "Error: File not found or cannot be opened!" << endl;
        return 1;
    }

    char ch;
    while (input.get(ch)) {
        ch = ch ^ key;  // XOR encryption/decryption
        output.put(ch);
    }

    input.close();
    output.close();

    cout << "\nProcess completed successfully!\n";
    cout << "Output file: " << outname << endl;
    cout << "(Run again with same key to decrypt the image)\n";

    return 0;
}





Q7 : 

HTML : 
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>Simple Password Demo</title>
</head>
<body>
  <h2>Register</h2>
  Username: <input id="regUser" type="text"><br>
  Password: <input id="regPass" type="password"><br>
  Iterations: <input id="iter" type="number" value="100000"><br>
  <button id="btnRegister">Register</button>
  <div id="regMsg"></div>

  <hr>

  <h2>Login</h2>
  Username: <input id="loginUser" type="text"><br>
  Password: <input id="loginPass" type="password"><br>
  <button id="btnLogin">Login</button>
  <div id="loginMsg"></div>

  <hr>

  <h2>Stored (simulated server DB)</h2>
  <pre id="dbView">{}</pre>
  <button id="btnClear">Clear Storage</button>

  <script src="script.js"></script>
</body>
</html>


JS : 

// Simple two-file demo: index.html + script.js
// Uses PBKDF2 (client-side) + per-user salt and localStorage as simulated DB.

// Helpers
const enc = new TextEncoder();
const dec = new TextDecoder();

// simple Base64 convert (offline, no libs)
function toBase64(buffer) {
  return btoa(String.fromCharCode(...new Uint8Array(buffer)));
}
function fromBase64(base64) {
  return Uint8Array.from(atob(base64), c => c.charCodeAt(0)).buffer;
}

// generate random salt (bytes)
function genSalt(len = 16) {
  return crypto.getRandomValues(new Uint8Array(len)).buffer;
}

// PBKDF2 derive: returns ArrayBuffer (32 bytes)
async function derivePBKDF2(password, saltBuffer, iterations = 100000, keyLen = 32) {
  const baseKey = await crypto.subtle.importKey(
    'raw',
    enc.encode(password),
    { name: 'PBKDF2' },
    false,
    ['deriveBits']
  );
  const derived = await crypto.subtle.deriveBits(
    {
      name: 'PBKDF2',
      salt: saltBuffer,
      iterations: iterations,
      hash: 'SHA-256',
    },
    baseKey,
    keyLen * 8
  );
  return derived;
}

// simulated DB in localStorage
const DB_KEY = 'demo_pw_db_v2';
function loadDB() {
  try {
    return JSON.parse(localStorage.getItem(DB_KEY) || '{}');
  } catch (e) {
    return {};
  }
}
function saveDB(db) {
  localStorage.setItem(DB_KEY, JSON.stringify(db));
}
function refreshDBView() {
  document.getElementById('dbView').textContent = JSON.stringify(loadDB(), null, 2);
}

// UI refs
const regUser = document.getElementById('regUser');
const regPass = document.getElementById('regPass');
const iterInp = document.getElementById('iter');
const btnRegister = document.getElementById('btnRegister');
const regMsg = document.getElementById('regMsg');

const loginUser = document.getElementById('loginUser');
const loginPass = document.getElementById('loginPass');
const btnLogin = document.getElementById('btnLogin');
const loginMsg = document.getElementById('loginMsg');

const btnClear = document.getElementById('btnClear');

// lockout state (kept client-side for demo)
let lockState = {}; // username -> {fails, lockedUntilTimestamp}

// register
btnRegister.addEventListener('click', async () => {
  regMsg.textContent = '';
  const user = (regUser.value || '').trim();
  const pass = regPass.value || '';
  const iterations = Math.max(1000, Number(iterInp.value) || 100000);

  if (!user || !pass) {
    regMsg.textContent = 'Enter username and password';
    return;
  }

  const db = loadDB();
  if (db[user]) {
    regMsg.textContent = 'User already exists';
    return;
  }

  const salt = genSalt(16);
  const derived = await derivePBKDF2(pass, salt, iterations, 32);

  // store Base64 strings and iterations used
  db[user] = {
    salt: toBase64(salt),
    hash: toBase64(derived),
    iterations: iterations,
    created: new Date().toISOString(),
  };
  saveDB(db);
  refreshDBView();
  regMsg.textContent = 'Registered (stored salt + hash).';
  regUser.value = '';
  regPass.value = '';
});

// login
btnLogin.addEventListener('click', async () => {
  loginMsg.textContent = '';
  const user = (loginUser.value || '').trim();
  const pass = loginPass.value || '';

  if (!user || !pass) {
    loginMsg.textContent = 'Enter username and password';
    return;
  }

  // check lockout
  const now = Date.now();
  const state = lockState[user] || { fails: 0, lockedUntil: 0 };
  if (state.lockedUntil && now < state.lockedUntil) {
    loginMsg.textContent = `Account locked. Try after ${new Date(
      state.lockedUntil
    ).toLocaleTimeString()}`;
    return;
  }

  const db = loadDB();
  const record = db[user];
  if (!record) {
    loginMsg.textContent = 'Invalid credentials';
    state.fails++;
    lockState[user] = state;
    checkLock(user);
    return;
  }

  const saltBuf = fromBase64(record.salt);
  const derived = await derivePBKDF2(pass, saltBuf, record.iterations, 32);
  const derivedB64 = toBase64(derived);

  // constant-time-ish compare (simple)
  if (derivedB64 === record.hash) {
    loginMsg.textContent = 'Login successful ✅';
    // reset fail counters
    lockState[user] = { fails: 0, lockedUntil: 0 };
  } else {
    state.fails = (state.fails || 0) + 1;
    lockState[user] = state;
    checkLock(user);
    loginMsg.textContent = 'Invalid credentials';
  }
});

// check and apply lockout after 3 fails → lock 30 seconds, then bigger on repeated failures
function checkLock(user) {
  const state = lockState[user];
  if (!state) return;
  if (state.fails >= 3 && state.fails < 6) {
    state.lockedUntil = Date.now() + 30_000; // 30 seconds
  } else if (state.fails >= 6) {
    state.lockedUntil = Date.now() + 5 * 60_000; // 5 minutes
  }
  lockState[user] = state;
}

// clear storage
btnClear.addEventListener('click', () => {
  if (!confirm('Clear stored users?')) return;
  localStorage.removeItem(DB_KEY);
  lockState = {};
  refreshDBView();
  regMsg.textContent = '';
  loginMsg.textContent = '';
});

// init view
refreshDBView();






















Q4 : 


 #include <iostream>
using namespace std;

// Fast modular exponentiation: (base^exp) % mod
long long mod_exp(long long base, long long exp, long long mod) {
    long long res = 1;
    base %= mod;
    while (exp > 0) {
        if (exp & 1) res = (res * base) % mod;
        base = (base * base) % mod;
        exp >>= 1;
    }
    return res;
}

// Compute shared secret: otherPublic^private mod p
long long shared_secret(long long otherPub, long long priv, long long p) {
    return mod_exp(otherPub, priv, p);
}

int main() {
    // Prime (p) and generator (g)
    const long long p = 23;
    const long long g = 5;

    // Private keys
    const long long r  = 6;  // Rohan
    const long long ra = 15; // Raj
    const long long pr = 7;  // Pratham (attacker)

    // Public keys: g^private mod p
    const long long R   = mod_exp(g, r, p);  // Rohan's public
    const long long RA  = mod_exp(g, ra, p); // Raj's public
    const long long PR  = mod_exp(g, pr, p); // Pratham's public (used for MITM)

    cout << "Choose an option:\n1. Normal DH exchange\n2. MITM by Pratham\n> ";
    int choice; cin >> choice;

    if (choice == 1) {
        // Normal exchange: Rohan <-> Raj
        cout << "Rohan's Public : " << R  << "\n";
        cout << "Raj's Public   : " << RA << "\n";

        long long S_rohan = shared_secret(RA, r, p);
        long long S_raj   = shared_secret(R,  ra, p);

        cout << "Rohan's secret: " << S_rohan << "\n";
        cout << "Raj's secret  : " << S_raj   << "\n";

        cout << (S_rohan == S_raj ? "Secure communication established.\n"
                                : "Shared secrets do not match!\n");
    }
    else if (choice == 2) {
        // MITM scenario: Pratham intercepts and substitutes public keys
        cout << "Rohan's Public : " << R  << "\n";
        cout << "Raj's Public   : " << RA << "\n";

        // Attacker sends PR to both parties
        cout << "Pratham sends his public key to Rohan: " << PR << "\n";
        cout << "Pratham sends his public key to Raj  : " << PR << "\n";

        // Each party computes a secret (actually with Pratham)
        long long S_rohan = shared_secret(PR, r, p);  // Rohan <> Pratham
        long long S_raj   = shared_secret(PR, ra, p); // Raj   <> Pratham

        // Pratham computes both shared secrets using intercepted publics
        long long S_pr_rohan = shared_secret(R,  pr, p);  // with Rohan
        long long S_pr_raj   = shared_secret(RA, pr, p);  // with Raj

        cout << "Rohan computes secret (with Pratham): " << S_rohan << "\n";
        cout << "Raj   computes secret (with Pratham): " << S_raj   << "\n";
        cout << "Pratham's secret with Rohan         : " << S_pr_rohan << "\n";
        cout << "Pratham's secret with Raj           : " << S_pr_raj   << "\n";

        cout << ((S_rohan == S_pr_rohan && S_raj == S_pr_raj)
                 ? "MITM successful: Pratham can intercept/modify messages.\n"
                 : "MITM failed.\n");
    }
    else {
        cout << "Invalid option.\n";
    }
    return 0;
}











Q3 : 


#include <iostream>
#include <string>
using namespace std;

// Function to encrypt the text
string encrypt(string text, int key) {
    // Step 1: Reverse the text
    string reversed = string(text.rbegin(), text.rend());

    // Step 2: Shift each character by the key
    for (int i = 0; i < reversed.size(); i++) {
        reversed[i] = reversed[i] + key;
    }
    return reversed;
}

// Function to decrypt the text
string decrypt(string text, int key) {
    // Step 1: Reverse the shift
    for (int i = 0; i < text.size(); i++) {
        text[i] = text[i] - key;
    }

    // Step 2: Reverse the text back
    string original = string(text.rbegin(), text.rend());
    return original;
}

int main() {
    string message;
    int key;

    cout << "Enter your message: ";
    getline(cin, message);

    cout << "Enter key (number): ";
    cin >> key;

    string encrypted = encrypt(message, key);
    string decrypted = decrypt(encrypted, key);

    cout << "\nEncrypted Text: " << encrypted;
    cout << "\nDecrypted Text: " << decrypted << endl;

    return 0;
}


































Q 1 : 

#include <iostream>
#include <string>
#include <vector>
using namespace std;

// ---------- Caesar Cipher ----------
string caesarEncrypt(string msg, int key) {
    string res = "";
    for (char c : msg) {
        if (isalpha(c))
            res += char(((toupper(c) - 'A' + key) % 26) + 'A');
        else
            res += c;
    }
    return res;
}

string caesarDecrypt(string msg, int key) {
    string res = "";
    for (char c : msg) {
        if (isalpha(c))
            res += char(((toupper(c) - 'A' - key + 26) % 26) + 'A');
        else
            res += c;
    }
    return res;
}

// ---------- Polyalphabetic Cipher ----------
string polyEncrypt(string msg, string key) {
    string res = "";
    int j = 0;
    for (char c : msg) {
        if (isalpha(c)) {
            int shift = toupper(key[j % key.size()]) - 'A';
            res += char(((toupper(c) - 'A' + shift) % 26) + 'A');
            j++;
        } else res += c;
    }
    return res;
}

string polyDecrypt(string msg, string key) {
    string res = "";
    int j = 0;
    for (char c : msg) {
        if (isalpha(c)) {
            int shift = toupper(key[j % key.size()]) - 'A';
            res += char(((toupper(c) - 'A' - shift + 26) % 26) + 'A');
            j++;
        } else res += c;
    }
    return res;
}

// ---------- Vigenere Cipher ----------
string vigenereEncrypt(string msg, string key) {
    return polyEncrypt(msg, key); // same logic
}

string vigenereDecrypt(string msg, string key) {
    return polyDecrypt(msg, key); // same logic
}

// ---------- Vernam Cipher ----------
string vernamEncrypt(string msg, string key) {
    string res = "";
    for (int i = 0; i < msg.size(); i++)
        res += char(msg[i] ^ key[i]); // XOR
    return res;
}

string vernamDecrypt(string msg, string key) {
    return vernamEncrypt(msg, key); // same as encryption
}

// ---------- One-Time Pad ----------
string otpEncrypt(string msg, string pad) {
    return vernamEncrypt(msg, pad); // same XOR logic
}

string otpDecrypt(string msg, string pad) {
    return vernamEncrypt(msg, pad); // same as encryption
}

// ---------- Rail Fence Cipher ----------
string railEncrypt(string msg, int key) {
    vector<string> rail(key);
    int dir = 1, row = 0;
    for (char c : msg) {
        rail[row] += c;
        if (row == 0) dir = 1;
        else if (row == key - 1) dir = -1;
        row += dir;
    }
    string res = "";
    for (auto &r : rail) res += r;
    return res;
}

string railDecrypt(string msg, int key) {
    vector<vector<char>> rail(key, vector<char>(msg.size(), '\n'));
    int dir = 1, row = 0;
    for (int i = 0; i < msg.size(); i++) {
        rail[row][i] = '*';
        if (row == 0) dir = 1;
        else if (row == key - 1) dir = -1;
        row += dir;
    }
    int idx = 0;
    for (int i = 0; i < key; i++)
        for (int j = 0; j < msg.size(); j++)
            if (rail[i][j] == '*' && idx < msg.size())
                rail[i][j] = msg[idx++];

    string res = "";
    row = 0; dir = 1;
    for (int i = 0; i < msg.size(); i++) {
        res += rail[row][i];
        if (row == 0) dir = 1;
        else if (row == key - 1) dir = -1;
        row += dir;
    }
    return res;
}

// ---------- MAIN ----------
int main() {
    string msg, key;
    int k;

    cout << "Enter message: ";
    getline(cin, msg);

    cout << "\n1. Caesar Cipher\n2. Polyalphabetic\n3. Vigenere\n4. Vernam\n5. One-Time Pad\n6. Rail Fence\nChoose: ";
    int ch; cin >> ch;

    switch (ch) {
        case 1:
            cout << "Enter key: "; cin >> k;
            cout << "Encrypted: " << caesarEncrypt(msg, k) << endl;
            cout << "Decrypted: " << caesarDecrypt(caesarEncrypt(msg, k), k) << endl;
            break;

        case 2:
            cout << "Enter key: "; cin >> key;
            cout << "Encrypted: " << polyEncrypt(msg, key) << endl;
            cout << "Decrypted: " << polyDecrypt(polyEncrypt(msg, key), key) << endl;
            break;

        case 3:
            cout << "Enter key: "; cin >> key;
            cout << "Encrypted: " << vigenereEncrypt(msg, key) << endl;
            cout << "Decrypted: " << vigenereDecrypt(vigenereEncrypt(msg, key), key) << endl;
            break;

        case 4:
            cout << "Enter key (same length as msg): "; cin >> key;
            cout << "Encrypted: " << vernamEncrypt(msg, key) << endl;
            cout << "Decrypted: " << vernamDecrypt(vernamEncrypt(msg, key), key) << endl;
            break;

        case 5:
            cout << "Enter pad (same length as msg): "; cin >> key;
            cout << "Encrypted: " << otpEncrypt(msg, key) << endl;
            cout << "Decrypted: " << otpDecrypt(otpEncrypt(msg, key), key) << endl;
            break;

        case 6:
            cout << "Enter key (number of rails): "; cin >> k;
            cout << "Encrypted: " << railEncrypt(msg, k) << endl;
            cout << "Decrypted: " << railDecrypt(railEncrypt(msg, k), k) << endl;
            break;

        default:
            cout << "Invalid choice!\n";
    }
    return 0;
}









Q 6 :

import random
import hashlib

def is_prime(num):
    if num <= 1:
        return False
    for i in range(2, int(num ** 0.5) + 1):
        if num % i == 0:
            return False
    return True

def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a

def mod_inverse(a, m):
    for i in range(1, m):
        if (a * i) % m == 1:
            return i
    return None

def generate_keypair():
    p = q = 1
    while not is_prime(p):
        p = random.randint(100, 1000)
    while not is_prime(q) or p == q:
        q = random.randint(100, 1000)
    n = p * q
    phi = (p - 1) * (q - 1)
    e = random.randint(2, phi - 1)
    while gcd(e, phi) != 1:
        e = random.randint(2, phi - 1)
    d = mod_inverse(e, phi)
    return (e, n), (d, n)

def rsa_encrypt(message, public_key):
    e, n = public_key
    return [pow(ord(char), e, n) for char in message]

def rsa_decrypt(encrypted_message, private_key):
    d, n = private_key
    return ''.join([chr(pow(char, d, n)) for char in encrypted_message])

def generate_signature(message, private_key):
    hashed_message = hashlib.sha256(message.encode()).hexdigest()
    return rsa_encrypt(hashed_message, private_key)

def verify_signature(message, signature, public_key):
    hashed_message = hashlib.sha256(message.encode()).hexdigest()
    decrypted_signature = rsa_decrypt(signature, public_key)
    return decrypted_signature == hashed_message

print("Generating keys for X (sender) and Y (receiver)...")
public_key_X, private_key_X = generate_keypair()
public_key_Y, private_key_Y = generate_keypair()

message = input("\nEnter message from X → Y: ")

encrypted_message = rsa_encrypt(message, public_key_Y)
signature = generate_signature(message, private_key_X)

print("\nEncrypted Message:", encrypted_message)
print("Signature:", signature)

try:
    pr_x = "test"
    de = rsa_decrypt(encrypted_message, pr_x)
    print("Z trying to read message:", de)
except:
    print("Z (attacker) failed to decrypt message — not authorized.")

decrypted_message = rsa_decrypt(encrypted_message, private_key_Y)
is_valid = verify_signature(decrypted_message, signature, public_key_X)

print("\nReceiver Side:")
print("Decrypted Message:", decrypted_message)
if is_valid:
    print("Signature Verified — Message Integrity and Authenticity Confirmed.")
else:
    print("Signature Invalid — Message may have been tampered.")

















Q 5  :




import hashlib

# Get message from user
message = input("Enter message to send: ")

# Sender calculates SHA-1 hash
sender_hash = hashlib.sha1(message.encode()).hexdigest()
print("\n[SENDER]")
print("Message:", message)
print("SHA-1 Hash:", sender_hash)

# Simulate sending message over the network
received_message = message

# Receiver calculates SHA-1 hash
receiver_hash = hashlib.sha1(received_message.encode()).hexdigest()
print("\n[RECEIVER]")
print("Received Message:", received_message)
print("Computed Hash:", receiver_hash)

# Compare both hashes
if sender_hash == receiver_hash:
    print("\n Message integrity verified — message not changed.")
else:
    print("\n Message integrity failed — message was modified.")

















Q 2 : 


Without sender receiver : 

import random
import time
import math

def is_prime(n):
    if n <= 1:
        return False
    for i in range(2, int(math.sqrt(n)) + 1):
        if n % i == 0:
            return False
    return True

def gcd(a, b):
    while b:
        a, b = b, a % b
    return a

def extended_gcd(a, b):
    if a == 0:
        return b, 0, 1
    g, x1, y1 = extended_gcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return g, x, y

def mod_inverse(e, phi):
    g, x, _ = extended_gcd(e, phi)
    if g != 1:
        raise ValueError("Inverse doesn't exist")
    return x % phi

def find_coprime(phi):
    while True:
        e = random.randint(2, phi - 1)
        if gcd(e, phi) == 1:
            return e



print("=== RSA Secure Communication Simulation ===\n")

# Step 1: Key Generation
p = int(input("Enter first prime number (p): "))
q = int(input("Enter second prime number (q): "))

if not (is_prime(p) and is_prime(q)):
    print("❌ Both p and q must be prime!")
else:
    n = p * q
    phi = (p - 1) * (q - 1)
    e = find_coprime(phi)
    d = mod_inverse(e, phi)

    print(f"\n Public Key: (e={e}, n={n})")
    print(f" Private Key: (d={d}, n={n})\n")

    # Step 2: Encryption
    while True:
        try:
            plaintext = int(input("Enter integer plaintext to encrypt: "))
            if plaintext <= 0 or plaintext >= n:
                raise ValueError("Plaintext must be between 1 and n-1.")
            break
        except ValueError as ve:
            print(f"Invalid input: {ve}. Try again.")

    start_enc = time.perf_counter()
    cipher_text = pow(plaintext, e, n)
    enc_time = time.perf_counter() - start_enc

    print(f"\nCiphertext → {cipher_text}")
    print(f"Encryption Time → {enc_time:.6f} seconds")

    # Step 3: Decryption
    start_dec = time.perf_counter()
    decrypted_text = pow(cipher_text, d, n)
    dec_time = time.perf_counter() - start_dec

    print(f"\nCiphertext received → {cipher_text}")
    print(f"Decrypted Text → {decrypted_text}")
    print(f"Decryption Time → {dec_time:.6f} seconds")

    # Step 4: Verification
    if decrypted_text == plaintext:
        print("\n✅ Message Integrity Verified: The message is not altered.")
    else:
        print("\n⚠️ Message Integrity Failed: The message was altered!")







 




