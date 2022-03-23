//
//  main.swift
//  ECC-swift
//
//  Created by wei li on 2022/3/7.
//

import Foundation


func readDataFromStdIn() -> Data{
    var c = 0 as  Int32
    // 30M
    let bfsize = (1 << 20) * 30
    let buffer = malloc( bfsize ).bindMemory(to: UInt8.self, capacity: bfsize)
    var t = 0;
    c = fgetc(stdin);
    repeat{
        buffer[t] = UInt8(c);
        t += 1;
        
        c = fgetc(stdin);
    }while c != EOF
    
    free(buffer)
    return Data(bytes: buffer, count: t);
    
}

func printKey(key:Data){
    let dataHash = try? LTBase64.base64Decode(key.sha256(base64: 1));
    let randomart = RandomArt.randomArt(data: dataHash! , title: "[Secp251k1]", end: "[SHA 256]");
    
    print("ECC encryption privateKey finggerprint:\n\(key.sha256(base64: 1))\nrandomart:\n\(randomart)");
    
    var ZeroCount = 0;
    var OneCount = 0;
    for var p in key{
        var c = 0
        while(p != 0) {
            p &= (p-1)
            c += 1;
        }
        OneCount += c;
        ZeroCount += 8-c;
    }
    print("0/1 = \(ZeroCount)/\(OneCount)");

    
//    bit map
//    for i in 0..<key.count{
//        if(i % 3 == 0){
//            print("");
//        }
//        let p = key[i];
//        for j in 0..<8{
//            if((p & (1 << j)) != 0){
//                print("o" ,separator: "",terminator: "");
//            }else{
//                print("." ,separator: "",terminator: "");
//            }
//        }
//    }
//    print("\n")
    
}



let helpMsg = """
ecc 0.1.1
https://github.com/vitock/LTEcc\
g [-prikey/secKey/s prikey]  generate keypair [-k  passphrase/count] [-S] saveto key chain
e  -pubkey/p pubkey -m msg [-f inputfilepath] [-o outpath]
d  -prikey/s prikey -m base64ciphermsg  binary data from stdin [-f inputfilepath] [-o outpath]
r  -m msg print random art of msg
s  show saved key in keychain
        
-z set 0 if you dont want gzip
"""

repeat{
    if CommandLine.arguments.count <= 1{
        print(helpMsg)
        break;
    }
    
    
    var strPreKey:String?
    var dicArg = Dictionary<String,Any>();
    for i in 1..<CommandLine.arguments.count{
        Lprint(CommandLine.arguments[i])
        let argument = CommandLine.arguments[i];
        if argument.hasPrefix("-"){
            var strKey = argument;
            strKey = String(argument[argument.index(argument.startIndex, offsetBy: 1)..<argument.endIndex])
            Lprint(argument,strKey)
            strPreKey = strKey;
            continue;
        }
        
        let strValue = argument;
        if strPreKey != nil{
            let preValue = dicArg[strPreKey!];
            if (preValue == nil ){
                dicArg[strPreKey!] = strValue
            }
            else if preValue is [Any]{
                var arr = preValue as! [Any]
                arr.append(strValue)
            }else if(strPreKey == "f"){
                var arr = [Any]();
                if(preValue != nil){
                    arr.append(preValue!)
                }
                arr.append(strValue)
                dicArg[strPreKey!] = arr
            }
        }
        
        
        
        
        
        let cmd = CommandLine.arguments[1];
        var strSecKey = dicArg["s"] as! String?
        if strPreKey == nil{
            strSecKey = dicArg["secKey"] as! String?
        }
        if strPreKey == nil{
            strSecKey = dicArg["prikey"] as! String?
        }
      
        
        switch cmd {
        case "g":
            let keyphrase = dicArg["k"] as! String?
            if keyphrase != nil && strSecKey != nil {
                print("seckey [s] is specified,the key phrass [k] will be ignored");
            }
            else if(keyphrase != nil){
                Lprint("to be done")
            }else {
                let kp = try? LTEccTool.shared.genKeyPair(strSecKey, keyPhrase:keyphrase )
                
                let keyData = try?  LTBase64.base64Decode(kp!.priKey);
                printKey(key: keyData!)
                
                print("publickey:\(kp!.pubKey)\nprivatekey:\(kp!.priKey)")
                
            }
            
        case "e":
            var strPubKey = dicArg["p"] as!  String?
            if (strPubKey == nil  ) {
                strPubKey = dicArg["pubKey"] as!  String?
            }
            if (strPubKey == nil){
                strPubKey = LEccKeyChain.shared.getPublicKeyInKeychain();
            }
            
            if(strPubKey == nil){
                print("need pubkey ,use -p pubkey");
                exit(1);
            }
            
            
            print("3x")
        case "d":
            print("3x")
        case "r":
            print("3x")
        case "s":
            print("3x")
            
        default:
            print(helpMsg)
        }
        print(cmd)
        
        
        
        
    }
     
    Lprint(dicArg)
    
    
}while false
