//
//  keychaintool.swift
//  ECC-swift
//
//  Created by wei li on 2022/3/23.
//

import Foundation
import SSKeychain
class LEccKeyChain {
    private  let seckeyforkeychain = "y1NsDrXnvQfx1DxyebUALOAjpGuUojANwWbpO4y/x90="
    private  let pubkeyforkeychain = "ArLLgvLL7eoER5gPJ6eFhj4T3GPzSMOlLxxlJ5leG75R"
    static let shared = LEccKeyChain();
    
    func saveKeyInKeychain(secureKey:String,publicKey:String){
        let dataSec = try? LTEccTool.shared.ecEncrypt(data: secureKey.data(using: .utf8)!, pubKey: pubkeyforkeychain ,type:CryptAlgorithm.aes256)
        let dataPub = try? LTEccTool.shared.ecEncrypt(data: publicKey.data(using: .utf8)!, pubKey: pubkeyforkeychain ,type:CryptAlgorithm.aes256)
        
        if dataSec != nil && dataPub != nil{
            SSKeychain.setPassword(dataSec?.base64EncodedString(), forService: "vitock.ecc.privatekey", account: "bd454dc28bdd8ffda5c775185ccc9814");
            
            SSKeychain.setPassword(dataPub?.base64EncodedString(), forService: "vitock.ecc.publickey", account: "e46c6231b528cd74e81570e0409eac2a");
        }
    }
     
    func getPublicKeyInKeychain()->String?{
        
        let P = ProcessInfo.processInfo.environment["EC_PUBKEY"]
        if P != nil && P is String{
            return P;
        }
        
        var err : NSError? = nil
        let strvalue =  SSKeychain .password(forService: "vitock.ecc.publickey", account: "e46c6231b528cd74e81570e0409eac2a",error: &err);
        if err != nil{
            print(err!)
        }
        guard strvalue != nil else{
            return nil
        }
        
        let data = try? LTBase64.base64Decode(strvalue!);
        if data != nil {
            let finalkey = try? LTEccTool.shared.ecDecrypt(encData: data!, priKey: seckeyforkeychain);
            
            if(finalkey != nil){
                let r = String(data: finalkey!, encoding: .utf8)
                return r;
            }
            
            return nil;
        }
        
        
        return nil;
        
    }
    
    func getPrivateKeyInKeychain()->String?{
        let S = ProcessInfo.processInfo.environment["EC_SECKEY"]
        if S != nil && S is String{
            return S;
        }
        
        var err: NSError? = nil;
        let strvalue =  SSKeychain .password(forService: "vitock.ecc.privatekey", account: "bd454dc28bdd8ffda5c775185ccc9814" ,error: &err);
        if err != nil{
            print(err!)
        }
        guard strvalue != nil else{
            return nil
        }
        
        let data = try? LTBase64.base64Decode(strvalue!);
        if data != nil {
            let finalkey = try? LTEccTool.shared.ecDecrypt(encData: data!, priKey: seckeyforkeychain);
            
            if(finalkey != nil){
                let r = String(data: finalkey!, encoding: .utf8)
                return r;
            }
            
            return nil;
        }
        
        
        return nil;
        
    }
    
}
