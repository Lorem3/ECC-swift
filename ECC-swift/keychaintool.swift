//
//  keychaintool.swift
//  ECC-swift
//
//  Created by wei li on 2022/3/23.
//

import Foundation

class LEccKeyChain {
    private  let seckeyforkeychain = "y1NsDrXnvQfx1DxyebUALOAjpGuUojANwWbpO4y/x90="
    private  let pubkeyforkeychain = "ArLLgvLL7eoER5gPJ6eFhj4T3GPzSMOlLxxlJ5leG75R"
    static let shared = LEccKeyChain();
     
    func getPublicKeyInKeychain()->String?{
        let strvalue =  SSKeychain .password(forService: "vitock.ecc.publickey", account: "e46c6231b528cd74e81570e0409eac2a");
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
        let strvalue =  SSKeychain .password(forService: "vitock.ecc.privatekey", account: "bd454dc28bdd8ffda5c775185ccc9814");
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
