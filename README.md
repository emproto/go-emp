# go-emp : Encrypted Message Protocol implementation

## Overview [![GoDoc](https://godoc.org/github.com/emproto/go-emp?status.svg)](https://godoc.org/github.com/emproto/go-emp)

This repository contains a reference implementation of Encrypted Message Protocol in Go programming language.

It is not aimed to give universal solution. Instead it implements some popular types on encrypted messages, such as:
- RSA encrypted with SHA-256/SHA-512 signing
- ECDSA encrypted with SHA-256/SHA-512 signing
- AES128 and AES256 encrypted without signing

## Install

```
go get github.com/emproto/go-emp
```

## How to generate RSA keys

```
mkdir -p ~/.keys/emproto
ssh-keygen -m pem -t rsa -f ~/.keys/emproto/id_rsa
openssl rsa -in ~/.keys/emproto/id_rsa -pubout -out ~/.keys/emproto/id_rsa.pub.pem
```

## Code example

```go
import (
    "io/ioutil"
    "os"

    "github.com/emproto/go-emt"
)

func createMessage(text string) []byte {
    privKey := ioutil.ReadFile(os.ExpandVar("~/.keys/emproto/id_rsa"))
    pubKey := ioutil.ReadFile(os.ExpandVar("~/.keys/emproto/id_rsa.pub.pem"))

    msg := emp.NewRsaSha256Message("Hello, Secure World!")
    
    err := msg.Encrypt(pubKey)
    if err != nil {
        panic(err)
    }
    
    err := msg.Sign(privKey)
    if err != nil {
        panic(err)
    }
    
    packedMessage, _ := emp.PackBase64(msg)
    
    receiveMessage(packedMessage)
}

func receiveMessage(msgBytes []byte) {
    privKey := ioutil.ReadFile(os.ExpandVar("~/.keys/emproto/id_rsa"))
    pubKey := ioutil.ReadFile(os.ExpandVar("~/.keys/emproto/id_rsa.pub.pem"))
    
    rawMessage, _ := emp.UnpackBase64(msgBytes)
    rsaMessage := LoadRsaMessage(rawMessage)
    
    err := rsaMessage.Verify(pubKey)
    if err != nil {
        panic("cannot verify message")
    }
    
    rawMsgBytes, err := rsaMessage.Decrypt(privKey)
    if err != nil {
        panic(err)
    }
    
    fmt.Println(string(rawMsgBytes))
}
```

## License

MIT.
