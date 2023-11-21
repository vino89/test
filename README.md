### CAA - LAB2 - Victor Nondjock
# Rapport

## Challenge 1

### 1.1
Il y a 2 différences avec la version de la RFC (voir dernière page de ce document). 

La première se trouve dans la fonction `sign()`, elle est mise en évidence ici et suivie de la ligne correcte en commentaire. `h` est multipliéé par `r` au lieu de `a`, on peut donc simplifié et `S` vaut :

 $\ (h + 1) * r$ $mod$ $l$  

La secconde se trouve dans `verify()`, elle est mise en évidence de la même façon et a pour conséquence que `rhs` vaut :

$(h + 1) * R$


```    
def sign(self, privkey, pubkey, msg, ctx, hflag):
    .
    .
    .
    # Calculate s.
    S = to_bytes(((r + h * r) % self.l), self.b // 8, byteorder="little")
    #S=((r+h*a)%self.l).to_bytes(self.b//8,byteorder="little")
    .
    .
    .
    # The final signature is a concatenation of R and S.
    return R + S


def verify(self, pubkey, msg, sig, ctx, hflag):
    .
    .
    .    
    # Calculate left and right sides of check eq.
    rhs = R + (R * h)
    #rhs=R+(A*h)

    lhs = self.B * S
    for _ in range(0, self.c):
        lhs = lhs.double()
        rhs = rhs.double()
    # Check eq. holds?
    return lhs == rhs

```

Pour le "bon" fonctionnement du processus, la première différence est nécessaire pour correspondre lors de la vérification mais elle ne présente pas d'intérêt dans notre recherche.

### 1.2

Étant donné le $lhs = rhs$ résultant et le fait que l'on maitrise `R` et `S`, On peut facilement manipuler l'équation de façon à se retrouver avec un $0 = 0$ :

```
Signature devant être transmise
bytearray(b'\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')

(en base64)
sig = b'AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=='
```

### 1.3

Cette signature est la concaténation de la valeur 0 en base64 pour `S` avec l'encodage du point à l'infini pour `R`. 


```
R = (B * 0).encode()
sig = R + to_bytes(0,32, byteorder="little")
```

En transmettant cette signature, on peut en fait, signer n'importe quel message car, peu importe ce que valent les autres paramètres, la comparaison $lhs = rhs$ vaudra toujours 0.

## Challenge 2

### 2.1
Dans la partie 2, l'erreur est de ne pas avoir hashé  ni tronquer la clé privée avant de la concaténer au message.

La variable `r` contient la seconde erreur, en plus de souffrir de la première. On prend la moitié MSB de `khashMessage` (qui est donc déjà mal initialisé), plutôt que la moitié LSB.

C'est le résultat de ces 2 erreurs qui pourra être exploité pour la suite.

```
def sign(self, privkey, pubkey, msg, ctx, hflag):
    .
    .
    .
    khashMessage = self.H(privkey + msg, None, None)
    # Ici la clé privée devrait être hashée et tronquée avant d'être concaténée au message    
    
    # Calculate r and R (R only used in encoded form).
    r = from_le(self.__clamp(khashMessage[:self.b // 8])) % self.l
    #r=from_le(self.H(seed+msg,ctx,hflag))%self.l

    R = (self.B * r).encode()
    # Calculate h.
    khash = self.H(privkey, None, None)
    .
    .
    .
    return R + S
```

### 2.2

```
Signature devant être transmise
bytearray(b'OK\xd4\x83\xc0\x87\xcd\x82\t\xba\x94X@C\x16A\xe2\xf2\xe9\xb8\x04\x90\x96\t\xac\
x8dr\xdcyv\x92Bn\xb8h\xed\xed\x10D\xe0)Hbe\xdd\x80(\x04a\xd1W\x8b\xac\x9cX\x0c')
```

### 2.3
La fonction ci-dessous permet de forger la signature de la section précédente qui peut correspondre au message visé :

```
def forgSig(msg, emptySig, pubK, l):
    #Hash de A||A +1
    HA = Ed25519_inthash(pubK + pubK, None, None)
    HA = int.from_bytes(HA, "little")
    HA += 1
    HA %= l

    ###--- RETRIEVE EMPTY S
    SRaw = emptySig[32:]
    S = from_le(SRaw)
    ##--- RETRIEVE EMPTY R
    RRaw = emptySig[:32]

    ###--- RETRIEVE s
    fieldF = Field(S, l)
    field2F = Field(HA, l)
    s = int.from_bytes(fieldF.__truediv__(field2F).tobytes(32), "little")

    ##---FINDING "rhs"
    HRAMF = Ed25519_inthash(RRaw + pubK + msg, None, None)
    HRAMF = int.from_bytes(HRAMF, "little")
    HRAMF %= l

    ##--- FORGING S
    SF = ((HRAMF + 1) * s) % l
    SF = int.to_bytes(SF, 32, "little")

    ###--- FORGING SIGNATURE
    sigF = RRaw + SF
    #print("sigF: ", sigF)

    return sigF #b64encode(sigF)
```

On commence par signer un message vide sur le site. 

Grâce à la première erreur du code et puisque le message est vide la ligne suivante met uniquement le hash de la clé privée, dans `khashMessage`.

La 2ème erreur a pour conséquence de mettre les 256MSB du hash de la clé privée modulo l, dans `r`, le résultat est que `r` a la même valeur que `s`. Le résultat de ces étapes est que le `S` de la signature rendue vaut $s + h * s$.

`R` étant le résultat de $r*B$, elle vaut $s*B = A$ et ainsi $h = H(R||A) = H(A||A)$.

 On peut ensuite calculer $s = S/(h+1)$ et `s` ne change jamais car il ne dépend que de la clé privée.

Une fois le `s` découvert, on peut calculer le `h` du vrai message, celui qui sera calculer dans la fonction de vérification, si l'on fixe le `R` transmis. On peut par exemple prendre celui que l'on a récupérer du message vide, en calculant le hash $h = H(R||A||flag)$. On l'incrémente ensuite 1 et on peut ainsi calculer le `S` correspondant au flag qui équilibre l'équation $S*B = R+A*h$.

```
khashMessage = self.H(privkey + msg, None, None)
```

## Challenge 3

### 3.1

Pour la 3ème partie, il n'y a pas vraiment une partie "fausse", puisque notre collègue a crée sa propre version prenant la date en compte. Le problème est en fait que le `r` ne change jamais, car la date n'intervient pas dans son calcul. Ainsi la signature d'un même message n'aura que la seconde partie qui diffère à une date différente.

### 3.2

```
bytearray(b'\xd0\x9cV\xec6\xa0G\xfet\xcd\x0fe\xd8/\xb0\xf4\x08-s\x8f\xc9{\x81_\xc8}\x10\x03\x14M\xc1\xadO\xd6;i\xac\xfe\x98\x02\x04\x16{\xbd=\xfd\xf0\xcd\x969B\x07a\xf9\xb5\xb5\xfa\xd1\xfb\xa8\x8dO\n\x00')
```

### 3.3
Si l'on signe 2 fois le même message avec une date différente, seul `S` et `h` changent dans $S=r+h*s$.

On commence par calculer $h2=H(R||A||msg||date1)$ et $h2=H(R||A||msg||date2)$.

On a maintenant $S1=r+h1*a$ et $S2=r+h2*a$ et si on soustrait la seconde équation à la première on obtient $S1-S2=r+a(h1-h2)$ et une fois transformée $a=(S1-S2)/(h1-h2)$. On peut maintenant calculer $r=S1/h1*a$, le `a` trouvé importe peu car le `r` correspondra.

Finalement, on calcule le vrai $h=(R||A||flag||date)$ avec la date choisie et le `R` récupérer précédemment, on a tous les éléments pour calculer le `S`.

### 3.4

Pour corriger l'erreur de l'implémentation, il suffit, selon analyse, d'ajouter la date au hash de la clé privée. Le même message ne donne plus la même signature à des dates différentes et évite donc cette attaque. Cette méthode permet de vérifier que la date correspond au message signé. 



## Version RFC 8032
```
def sign(self,privkey,pubkey,msg,ctx,hflag):
    #Expand key.
    khash=self.H(privkey,None,None)
    a=from_le(self.__clamp(khash[:self.b//8]))
    seed=khash[self.b//8:]
    #Calculate r and R (R only used in encoded form).
    r=from_le(self.H(seed+msg,ctx,hflag))%self.l
    R=(self.B*r).encode()
    #Calculate h.
    h=from_le(self.H(R+pubkey+msg,ctx,hflag))%self.l
    #Calculate s.
    S=((r+h*a)%self.l).to_bytes(self.b//8,byteorder="little")
    #The final signature is a concatenation of R and S.
    return R+S

#Verify signature with public key.
def verify(self,pubkey,msg,sig,ctx,hflag):
    #Sanity-check sizes.
    if len(sig)!=self.b//4: return False
    if len(pubkey)!=self.b//8: return False
    #Split signature into R and S, and parse.
    Rraw,Sraw=sig[:self.b//8],sig[self.b//8:]
    R,S=self.B.decode(Rraw),from_le(Sraw)
    #Parse public key.
    A=self.B.decode(pubkey)
    #Check parse results.
    if (R is None) or (A is None) or S>=self.l: return False
    #Calculate h.
    h=from_le(self.H(Rraw+pubkey+msg,ctx,hflag))%self.l
    #Calculate left and right sides of check eq.
    rhs=R+(A*h)
    lhs=self.B*S
    for i in range(0, self.c):
        lhs = lhs.double()
        rhs = rhs.double()
    #Check eq. holds?
    return lhs==rhs
```
