//
//  keychaintool.swift
//  ECC-swift
//
//  Created by wei li on 2022/3/23.
//

import Foundation
import SSKeychain
import CryptoKit
class LEccKeyChain {
    private  let seed = "vitock.ecc"
    static let shared = LEccKeyChain();
    
    private func pubKeyForAccount(_ acc:String) -> String{
        
        var mac = [UInt8](repeating: 0, count: 32);
        HMAC.hmac(type: .blake2b, key: seed , keyLen: seed.count, msg: acc, msgLen: acc.count, mac: &mac, macLen: 32);
        
        
       
        let pub = try! LTEccTool.Curve25519.genKeyPair(mac.base64String()).pubKey

        return pub
        
    }
    private func secKeyForAccount(_ acc:String) -> String{
        var mac = [UInt8](repeating: 0, count: 32);
        HMAC.hmac(type: .blake2b, key: seed , keyLen: seed.count, msg: acc, msgLen: acc.count, mac: &mac, macLen: 32);
       
        return mac.base64String()
    }
    
    func saveKeyInKeychain(secureKey:String,publicKey:String,curveType:CurveType){
        
        let accSec = secKeyChainAcc(curveType: curveType)
        let accPub = pubKeyChainAcc(curveType: curveType)
        
        
        
        let dataSec = try? LTEccTool.ecEncrypt(data: secureKey.data(using: .utf8)!, pubKey: pubKeyForAccount(accSec) ,type:CryptAlgorithm.aes256)
        let dataPub = try? LTEccTool.ecEncrypt(data: publicKey.data(using: .utf8)!, pubKey: pubKeyForAccount(accPub) ,type:CryptAlgorithm.aes256)
        
        if dataSec != nil && dataPub != nil{
          
            SSKeychain.setPassword(dataSec?.base64EncodedString(), forService: "vitock.ecc.privatekey", account:  accSec);
            
            SSKeychain.setPassword(dataPub?.base64EncodedString(), forService: "vitock.ecc.publickey", account: accPub);
        }
    }
    
    func pubKeyChainAcc(curveType:CurveType) -> String{
        return curveType == .Curve25519 ? "341777dd307094bd951a6085af2b2427" : "e46c6231b528cd74e81570e0409eac2a"
    }
    func secKeyChainAcc(curveType:CurveType) -> String{
        return curveType == .Curve25519 ? "38b24d4d2854492301f38952d380cbe1" : "bd454dc28bdd8ffda5c775185ccc9814"
    }
    
    func environmentPubKey(curveType:CurveType) -> String{
        return curveType == .Curve25519 ? "EC_PUBKEY_X25519" : "EC_PUBKEY"

    }
    func environmentSecKey(curveType:CurveType) -> String{
        return curveType == .Curve25519 ? "EC_SECKEY_X25519" : "EC_SECKEY"

    }
    func getPublicKeyInKeychain(curveType:CurveType)->String?{
        
 
        let accPub = pubKeyChainAcc(curveType: curveType)
        
        
        let P = ProcessInfo.processInfo.environment[environmentPubKey(curveType: curveType)]
        if P != nil && P is String{
            return P;
        }
        
        var err : NSError? = nil
        let strvalue =  SSKeychain .password(forService: "vitock.ecc.publickey", account: accPub,error: &err);
        if err != nil{
            print(err!)
        }
        guard strvalue != nil else{
            return nil
        }
        
        
        
        let data = try? LTBase64.base64Decode(strvalue!);
        if data != nil {
            let finalkey = try? LTEccTool.ecDecrypt(encData: data!, priKey: secKeyForAccount(accPub));
            
            if(finalkey != nil){
                let r = String(data: finalkey!, encoding: .utf8)
                return r;
            }
            
            return nil;
        }
        
        
        return nil;
        
    }
    
    func getPrivateKeyInKeychain(curveType: CurveType)->String?{
        let S = ProcessInfo.processInfo.environment[environmentSecKey(curveType: curveType)]
        if S != nil && S is String{
            return S;
        }
        
        let accSec = secKeyChainAcc(curveType: curveType);
        
        var err: NSError? = nil;
        let strvalue =  SSKeychain .password(forService: "vitock.ecc.privatekey", account: accSec ,error: &err);
        if err != nil{
            print(err!)
        }
        guard strvalue != nil else{
            return nil
        }
        
        let data = try? LTBase64.base64Decode(strvalue!);
        if data != nil {
            let finalkey = try? LTEccTool.ecDecrypt(encData: data!, priKey: secKeyForAccount(accSec));
            
            if(finalkey != nil){
                let r = String(data: finalkey!, encoding: .utf8)
                return r;
            }
            
            return nil;
        }
        
        
        return nil;
        
    }
    
}
