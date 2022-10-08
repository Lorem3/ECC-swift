//
//  EC_X25519.swift
//  ECC-swift
//
//  Created by wei li on 2022/7/20.
//

import Foundation
typealias ECSecKeyPointer = UnsafeMutableRawPointer
typealias ECPubKeyPointer = UnsafeMutableRawPointer

enum CurveType {
    case Curve25519;
    case Secp256k1;
}

protocol ECFun{
    var curveType: CurveType{get}
    var secLen: Int {get}
    var pubLen: Int {get}
    var name: String {get}
 
    func genKeyPair(seckey:  ECSecKeyPointer,pubkey:  ECPubKeyPointer?)
    func genPubKey(seckey:  ECSecKeyPointer,pubkey:  ECPubKeyPointer)  
    func ecdh(secKeyA: ECSecKeyPointer,pubKeyB:ECPubKeyPointer,outBf64:UnsafeMutableRawPointer,sharePoint:ECPubKeyPointer?) throws
    
    func readPubKey(_ base64str:String,pubkey: ECPubKeyPointer) throws
    
    func readSecKey(_ base64str:String,seckey: ECSecKeyPointer) throws
    
    func seckeyToString(_ seckey:ECSecKeyPointer) throws -> String
    
    func pubkeyToString(_ pubkey:ECSecKeyPointer) throws -> String
    
    func generateSecBytes(_ secKey:ECSecKeyPointer);
    
    func convertPubKeyCanonical(pub:UnsafeRawPointer,pubSize:Int,toPub:ECPubKeyPointer) throws;
}




class EC_X25519:ECFun{
   
    
  
    
    var name: String {
        get {
            return "Curve25519"
        }
    }
    var curveType:CurveType{
        get{
            return .Curve25519
        }
    }
    var secLen: Int {
        get {
            return Int(crypto_kx_SECRETKEYBYTES)
        }
    }
    
    var pubLen :Int{
        get {
            return Int(crypto_kx_PUBLICKEYBYTES)
        }
    }
    
    let shareLen = Int(crypto_scalarmult_BYTES)
    
    func generateSecBytes(_ secKey:ECSecKeyPointer){
        genKeyPair(seckey: secKey, pubkey: nil)
    }
    
    func genKeyPair(seckey:  ECSecKeyPointer,pubkey:  ECPubKeyPointer?)  {
         
        let msgLen = 256;
        var tmp = [UInt8](repeating: 0, count:msgLen);
        var tmp2 = [UInt8](repeating: 0, count:Int(crypto_generichash_blake2b_KEYBYTES))
        
        var pk = [UInt8](repeating: 0, count: pubLen)
        var sk = [UInt8](repeating: 0, count: secLen)
         
        repeat{
            arc4random_buf(&tmp, msgLen)
            randombytes(&tmp2,UInt64(crypto_generichash_blake2b_KEYBYTES));
                          
            crypto_generichash(&sk,Int(secLen),tmp,UInt64(msgLen),tmp2,Int(crypto_generichash_blake2b_KEYBYTES))

            tmp.resetAllBytes()
            tmp2.resetAllBytes()
            
            
            sk[0] &= 248;
            sk[31] &= 127;
            sk[31] |= 64
            
            if(crypto_scalarmult_base(&pk, &sk) == 0 ){
                break
            }
        }while true
        
        
        memcpy(seckey, &sk, secLen)
        sk.resetAllBytes()
        if pubkey != nil {
            memcpy(pubkey, &pk, pubLen)
            pk.resetAllBytes()
        }
        
    }
    
    func genPubKey(seckey:  ECSecKeyPointer,pubkey:  ECPubKeyPointer){
        let sk = seckey.bindMemory(to: UInt8.self, capacity: Int(secLen));
        let pk = pubkey.bindMemory(to: UInt8.self, capacity: Int(pubLen));
        crypto_scalarmult_base(pk, sk)
    }
    func ecdh(secKeyA: ECSecKeyPointer,pubKeyB:ECPubKeyPointer,outBf64:UnsafeMutableRawPointer, sharePoint:ECPubKeyPointer? = nil ) throws {
        
        let sharelen = Int(crypto_scalarmult_BYTES)
        let skA = secKeyA.bindMemory(to: UInt8.self, capacity: Int(secLen));
        let pkB = pubKeyB.bindMemory(to: UInt8.self, capacity: Int(pubLen));

        var pkA = [UInt8](repeating: 0, count: Int(pubLen));
        var share =  [UInt8](repeating: 0, count: sharelen + Int(pubLen * 2));
        defer{
            share.resetAllBytes()
            pkA.resetAllBytes()
        }
        if(crypto_scalarmult(&share , skA , pkB) != 0){
            throw ECErr.ECDHError
        }
        
        if( sharePoint != nil ){
            memcpy(sharePoint, &share, sharelen)
        }
        
        
        /// 计算hash  sharePoint || Pub1 || Pub2
        if crypto_scalarmult_base(&pkA , skA) != 0 {
            throw ECErr.ECDHError
        }
        
         
        if (sodium_compare(&pkA, pkB, Int(pubLen)) < 0){
            memcpy(&share[sharelen], &pkA, Int(pubLen))
            memcpy(&share[sharelen + Int(pubLen)], pkB, Int(pubLen))
        }else{
            memcpy(&share[sharelen + Int(pubLen)], &pkA, Int(pubLen))
            memcpy(&share[sharelen], pkB, Int(pubLen))
        }
        
        let dh = outBf64.bindMemory(to: UInt8.self, capacity: 64);
        crypto_generichash(dh,64,&share,UInt64(share.count),nil,0);
        
        
        
        
    }
    
    func readPubKey(_ base64str:String,pubkey: ECPubKeyPointer) throws{
        let d = try LTBase64.base64Decode(base64str);
        if(d.count != pubLen){
            throw ECErr.PubkeyLengthError
        }
        _ = d.withUnsafeBytes { bf  in
            memcpy(pubkey , bf.baseAddress, bf.count)
        }
    }
    
    func readSecKey(_ base64str:String,seckey: ECSecKeyPointer) throws{
        let d = try LTBase64.base64Decode(base64str);
        if(d.count != secLen){
            throw ECErr.SeckeyDataError
        }
        _ = d.withUnsafeBytes { bf  in
            memcpy(seckey , bf.baseAddress, bf.count)
        }
    }
    
    func seckeyToString(_ seckey:ECSecKeyPointer) throws -> String {
        
        let d = Data(bytes: seckey, count: secLen)
        return   LTBase64.base64Encode(d)
    }
    
    func pubkeyToString(_ pubkey:ECSecKeyPointer) throws -> String {
        
        let d = Data(bytes: pubkey, count: pubLen)
        return   LTBase64.base64Encode(d)
    }
    
    func convertPubKeyCanonical(pub:UnsafeRawPointer,pubSize:Int,toPub:ECPubKeyPointer) throws{
        
        if pubLen == pubSize {
            memcpy(toPub, pub, pubSize)
        }else{
            throw ECErr.PubkeyLengthError
        }
    }
}
