//
//  EC.swift
//  ECC-swift
//
//  Created by wei li on 2022/4/13.
//

import Foundation
import Accelerate
import CommonCrypto
import libtommath
import secp256k1_swift
import Sodium


enum ECErr :Error{
    case PubkeyLengthError
    case PubkeyFormatError
    case PubkeyDataError
    
    case SeckeyDataError
    case SeckeyDataNotValid
    
    case ECDHError
}



class EC:ECFun{
    
    
    let pubKeyBufferLength = 33;
    let secKeyBufferLength = 32;
    private let XBufferLength = 32

    
    static let context = secp256k1_context_create(UInt32(SECP256K1_CONTEXT_SIGN|SECP256K1_CONTEXT_VERIFY))
    typealias ECPubKey = secp256k1_pubkey
    typealias ECSecKey = UnsafeMutableRawPointer
     
 
    
    
    /// big-Endian
    func readSecKey(_ base64String:String,keyOut:ECSecKey) throws {
        let data = try LTBase64.base64Decode(base64String)
        
        guard SECP256K1.verifyPrivateKey(privateKey:data) else{
            throw ECErr.SeckeyDataError
        }
         
        _ = data.withUnsafeBytes { bf  in
            memcpy(keyOut,  bf.baseAddress,data.count);
        }
         
 
       
    }
    
    func readPubKey(_ buffer:UnsafeRawPointer, count:Int ,R:inout ECPubKey) throws {
        
        
        guard count == 33 || count == 65 else {
            throw ECErr.PubkeyDataError
        }
        let keyLen: Int = count;
        var publicKey = secp256k1_pubkey()
        
        let res = withUnsafeMutablePointer(to: &publicKey) { pt  in
            secp256k1_ec_pubkey_parse(EC.context!, pt , buffer, keyLen);
        }
        
         
        if res == 0 {
            throw ECErr.PubkeyDataError;
        }
        R = publicKey;
         
         
    }
    func readPubKey(_ base64str:String,R:inout ECPubKey) throws{
        let data = Data(base64Encoded: base64str)!;
        
        data.withUnsafeBytes { bf  in
            try! readPubKey(bf.baseAddress!, count: bf.count,R:&R);
        }
    }
    
    /// here we just return 1 Point the other y2 = Prime - y1
    
    
    /// sha512(DH.X)
    func ecdhSha512(secKeyA: ECSecKey,pubKeyB:ECPubKey,outBf64:UnsafeMutableRawPointer){
        var bf = Data(capacity: 32);
        var dh =  pubKeyB;
        let res  = bf.withUnsafeMutableBytes { bf  in
            return withUnsafeMutablePointer(to: &dh) { pb  in
                return secp256k1_ec_pubkey_tweak_mul(EC.context!, pb , secKeyA)
            }
        }
        
        if res == 0  {
            return
        }
        
        
        let data = SECP256K1.serializePublicKey(publicKey: &dh ,compressed:true)!
        let dataX = data.subdata(in: 1..<data.count)
        _ = dataX.withUnsafeBytes { bf  in
            CC_SHA512(bf.baseAddress, CC_LONG(XBufferLength), outBf64.bindMemory(to: UInt8.self, capacity: Int(CC_SHA512_DIGEST_LENGTH)));
        }
   
    }
    
 
    
}

 


extension EC{
   
    
   
    
    var curveType:CurveType{
        get{
            return .Secp256k1
        }
    }
    var name: String {
        get {
            return "Secp256k1"
        }
    }
    var secLen: Int {
        get {
            return secKeyBufferLength
        }
    }
    
    var pubLen :Int{
        get {
            return pubKeyBufferLength
        }
    }
    
    
    func genKeyPair(seckey:  ECSecKeyPointer,pubkey:  ECPubKeyPointer?){
        
        let sec =  SECP256K1.generatePrivateKey()!
        let pub = SECP256K1.privateToPublic(privateKey: sec,compressed: true)!;
        _ = sec.withUnsafeBytes { bf  in
            memcpy(seckey, bf.baseAddress, bf.count);
        }
        
        _ = pub.withUnsafeBytes { bf  in
            memcpy(pubkey, bf.baseAddress, bf.count);
        }
        
    }
    func genPubKey(seckey:  ECSecKeyPointer,pubkey:  ECPubKeyPointer){
        let secData = Data(bytes: seckey, count: secKeyBufferLength);
        let pub = SECP256K1.privateToPublic(privateKey: secData,compressed: true)!;
        _ = pub.withUnsafeBytes { bf  in
            memcpy(pubkey, bf.baseAddress, bf.count);
        }
        
        
    }
    func ecdh(secKeyA: ECSecKeyPointer,pubKeyB:ECPubKeyPointer,outBf64:UnsafeMutableRawPointer ,sharePoint:ECPubKeyPointer? = nil) throws{
        
        
        var pub : ECPubKey = ECPubKey()
        try self.readPubKey(pubKeyB, count: pubKeyBufferLength, R: &pub);
        ecdhSha512(secKeyA: secKeyA, pubKeyB: pub, outBf64: outBf64);
    }
    
    func readPubKey(_ base64str:String,pubkey: ECPubKeyPointer) throws{
        let d =  try LTBase64.base64Decode(base64str);
        var R : ECPubKey = ECPubKey()
        try d.withUnsafeBytes { bf  in
            try self.readPubKey(bf.baseAddress!, count: bf.count, R: &R)
        };
        
        let datPub = SECP256K1.serializePublicKey(publicKey: &R ,compressed: true);
        if datPub != nil {
           _ =  datPub!.withUnsafeBytes({ bf   in
               memcpy(pubkey, bf.baseAddress , datPub!.count)
            })
        }else{
            throw ECErr.PubkeyDataError
        }
        
        
        
    }
    
    func readSecKey(_ base64str:String,seckey: ECSecKeyPointer) throws{
        let d = try  LTBase64.base64Decode(base64str)
        guard SECP256K1.verifyPrivateKey(privateKey: d) else{
            throw ECErr.SeckeyDataError
        }
        
        _ = d.withUnsafeBytes { bf  in
            memcpy(seckey, bf.baseAddress, bf.count)
        }
    }
    
    func seckeyToString(_ seckey:ECSecKeyPointer) throws -> String {
        let d = Data(bytes: seckey, count: secKeyBufferLength);
        return try LTBase64.base64Encode(d);
    }
    
    
    func convertPubKeyCanonical(pub:UnsafeRawPointer,pubSize:Int,toPub:ECPubKeyPointer) throws {
        if pubLen == pubSize {
            memcpy(toPub, pub, pubSize)
        }else{
            throw ECErr.PubkeyLengthError
        }
       
        
    }
    
    func pubkeyToString(_ pubkey:ECSecKeyPointer) throws -> String {
                
        let d = Data(bytes: pubkey, count: pubLen)
        return  LTBase64.base64Encode(d)
    }
    
    func generateSecBytes(_ outBf32:ECSecKeyPointer){
        SecRandomCopyBytes(kSecRandomDefault,secKeyBufferLength,outBf32)
    }
    
}
