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
    defer{
        free(buffer)
    }
    var t = 0;
    c = fgetc(stdin);
    repeat{
        buffer[t] = UInt8(c);
        t += 1;
        
        c = fgetc(stdin);
    }while c != EOF && t < bfsize
    
    let r = Data(bytes: buffer, count: t);
    return r;
    
}

func printKey(key:Data,title:String){
    let dataHash = try? LTBase64.base64Decode(key.sha256(base64: 1));
    let randomart = RandomArt.randomArt(data: dataHash! , title: "[\(title)]", end: "[SHA 256]");
    
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
    print("0/1 = \(ZeroCount)/\(OneCount) = \(Float(ZeroCount)/Float(OneCount))");
    
    
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

let Version = "2.2.0"

let helpMsg = """
ecc \(Version)
g [-prikey/secKey/s prikey]  generate keypair  [-S]  saveto key chain
e  -pubkey/p pubkey -m msg [-f inputfilepath] -r[recursion for directory]
   -a a:aes256 s:salsa20 default -size n[M]
d  -prikey/s prikey -m base64ciphermsg  binary data from stdin [-f inputfilepath] [-o outpath] -r[recursion for directory]
r  -m msg print random art of msg
s  show saved key in keychain

-size splite file with size MB


-c[urve] [s]ecp256k1 or [c]urve25519 [default]

-z 0 ,if don't want gzip File(-f) before encrypt, sepecify this

if you dont want to specify -s -p everytime ,
set EC_SECKEY* or EC_PUBKEY* on current ENV
export set EC_SECKEY*=...
export set EC_PUBKEY*=...
unset EC_PUBKEY* EC_SECKEY*
for Secp256k1 use
\(LEccKeyChain.shared.environmentPubKey(curveType: .Secp256k1))
\(LEccKeyChain.shared.environmentSecKey(curveType: .Secp256k1))
for Curve25519 use
\(LEccKeyChain.shared.environmentPubKey(curveType: .Curve25519))
\(LEccKeyChain.shared.environmentSecKey(curveType: .Curve25519))
"""

func main(){
    
    do{
        if CommandLine.arguments.count <= 1{
            print(helpMsg)
            return;
        }
        
        
        var dicArg = Dictionary<String,Any>();
        
        var i = 1, MaxCount = CommandLine.arguments.count
        while i < MaxCount{
            let argument = CommandLine.arguments[i];
            if(argument.hasPrefix("-")){
                var strKey = argument;
                strKey = String(argument[argument.index(argument.startIndex, offsetBy: 1)..<argument.endIndex])
                
                let files = NSMutableArray()
                if strKey == "f"{
                    dicArg[strKey] = files;
                    var j = i + 1;
                    while j < MaxCount{
                        let arg = CommandLine.arguments[j];
                        if arg .hasPrefix("-"){
                            i = j ;
                            break
                        }else{
                            files.add(arg);
                        }
                        j += 1
                    }
                    
                    i = j ;
                }else{
                    let j = i + 1;
                    if j < MaxCount{
                        let arg = CommandLine.arguments[j];
                        if arg .hasPrefix("-"){
                            dicArg[strKey] = "1"
                        }else{
                            dicArg[strKey] = arg
                        }
                    }else{
                        dicArg[strKey] = "1"
                    }
                    
                    i = j ;
                }
                
                
                
            }
            else{
                i += 1
            }
            
            
            
        }
        
        let cmd = CommandLine.arguments[1];
        var strSecKey = dicArg["s"] as! String?
        if strSecKey == nil{
            strSecKey = dicArg["secKey"] as! String?
        }
        if strSecKey == nil{
            strSecKey = dicArg["prikey"] as! String?
        }
        
        var curve = dicArg["curve"] as! String?
        if(curve == nil){
            curve = dicArg["c"] as! String?
        }
        
        
        let ectool :LTEccTool
        if curve != nil && curve!.lowercased() == "s"{
            ectool = LTEccTool.Secp255k1
        }else {
            ectool = LTEccTool.Curve25519
        }
        
        
        let sizeStr = dicArg["size"] as! String?
        var szMbFile  = sizeStr != nil ? Int(sizeStr!) : -1
        
        if szMbFile == nil  {
            szMbFile = -1
        }
        
        
        
        let EC_PUBKEY = LEccKeyChain.shared.environmentPubKey(curveType: ectool.ec.curveType)
        
        let EC_SECKEY = LEccKeyChain.shared.environmentSecKey(curveType: ectool.ec.curveType)
        
        
        switch cmd {
        case "g":
            
            
            let kp = try ectool.genKeyPair(strSecKey )
            
            let keyData = try  LTBase64.base64Decode(kp.priKey);
            if(true){
                printKey(key: keyData,title: ectool.ec.name)
                let resultStr = """
        prikey:\(kp.priKey)
        pubKey:\(kp.pubKey)
        unset \(EC_PUBKEY) \(EC_SECKEY)
        export set \(EC_PUBKEY)=\(kp.pubKey) \(EC_SECKEY)=\(kp.priKey)
        """
                print(resultStr)
            }
            
            
            if kp != nil && CommandLine.arguments.contains("-S"){
                
                print("\u{001B}[31;48m this action [-S] will overwite the key in keychain. continue[y/n] ? \u{001B}[0;0m")
                let s = readLine();
                if(s == "Y" || s == "y"){
                    LEccKeyChain.shared.saveKeyInKeychain(secureKey: kp.priKey, publicKey: kp.pubKey,curveType: ectool.curveType)
                }
            }
            
            
        case "e":
            var strPubKey = dicArg["p"] as!  String?
            if (strPubKey == nil  ) {
                strPubKey = dicArg["pubKey"] as!  String?
            }
            if (strPubKey == nil){
                strPubKey = LEccKeyChain.shared.getPublicKeyInKeychain(curveType: ectool.curveType);
            }
            
            
            if(strPubKey == nil){
                Lprint("need pubkey ,use -p pubkey");
                exit(1);
            }
            
            let files = dicArg["f"];
            
            if files != nil {
                
                let ss = dicArg["r"] as!  String?
                let recursion = ss  == "1"
                
                let gz = dicArg["z"] as! String?
                
                let zipType :ECCZipTyp
                if gz == "1" {
                    zipType = .gzip
                }else if gz == "0" {
                    zipType = .nogzip
                }else{
                    zipType = ECCZipTyp.auto
                }
                
                let t:CryptAlgorithm
                let atype = dicArg["a"] as! String?
                if(atype == "s"){
                    t = CryptAlgorithm.salsa20
                }else{
                    t = CryptAlgorithm.aes256
                }
                
                if files is Array<Any>{
                    
                   
                    for file in files as! [String] {
                        do {
                            try ectool.ecEncryptFile(filePath: file , outFilePath: nil , pubkeyString: strPubKey! ,zipType: zipType, alg:t,recursion:recursion,fileLengthMB: szMbFile!);
                        }
                        catch let e {
                            redPrint(e)
                        }
                        
                    }
                    
                }else if files is String{
                    try ectool.ecEncryptFile(filePath: files as! String, outFilePath: nil , pubkeyString: strPubKey!,zipType: zipType,alg:t,recursion:recursion,fileLengthMB: szMbFile!);
                }
                
                
                
                break
            }
            
            
            let strmsg = dicArg["m"] as! String?
            var dataMsg = strmsg?.data(using: .utf8);
            if(dataMsg == nil){
                dataMsg = readDataFromStdIn();
            }
            
            if dataMsg != nil {
                
                let t:CryptAlgorithm
                let atype = dicArg["a"] as! String?
                if(atype == "s"){
                    t = CryptAlgorithm.salsa20
                }else{
                    t = CryptAlgorithm.aes256
                }
                
                let z = (dicArg["z"] as! String? != "0") ? 1 : 0
                
                let d = try ectool .ecEncrypt(data: dataMsg!, pubKey: strPubKey!,zipfirst: z,type: t);
                
                _ = d.withUnsafeBytes({ bf  in
                    fwrite(bf.baseAddress, 1, bf.count, stdout);
                })
            }
            
            
        case "d":
            var seckey = dicArg["s"] as!  String?
            if (seckey == nil  ) {
                seckey = dicArg["prikey"] as!  String?
            }
            if (seckey == nil){
                seckey = LEccKeyChain.shared.getPrivateKeyInKeychain(curveType: ectool.curveType);
            }
            
            if(seckey == nil){
                Lprint("need seckey ,use  -s seckey");
                exit(1);
            }
            
            let files = dicArg["f"];
            let ss = dicArg["r"] as!  String?
            let recursion = ss  == "1"
            if files != nil {
                if files is Array<Any>{
                    
                    var map = Dictionary<String,Any>()
                    
                    for file0 in files as! [String] {
                        do{

                            let file :String
                            if LTEccTool.Curve25519.checkIsPartial(file0){
                                file = LTEccTool.Curve25519.setPartIndx(file0, idx: 1)
                                if map[file] != nil {
                                    print("skip",file0)
                                    continue
                                }
                                map[file] = "1"
                            }
                            else{
                                file = file0
                            }
                            
                            
                            
                            try LTEccTool.ecDecryptFile(filePath: file, outFilePath: nil , prikeyString: seckey!,recursion: recursion)
                        }
                        catch let e {
                            redPrint(e)
                            //                        Lprint(e);
                        }
                        
                    }
                    
                }else if files is String{
                    do{
                        try LTEccTool.ecDecryptFile(filePath: files as! String, outFilePath: nil , prikeyString: seckey!,recursion: recursion)
                    }catch let e {
                        Lprint(e)
                        redPrint(e)
                    }
                }
                
                
                
                break
            }
            
            
            let strmsg = dicArg["m"] as! String?
            var dataMsg = strmsg?.data(using: .utf8);
            if(dataMsg == nil){
                dataMsg = readDataFromStdIn();
            }
            
            if dataMsg != nil {
                let d = try LTEccTool.ecDecrypt(encData: dataMsg!, priKey: seckey!);
                
                _ = d.withUnsafeBytes({ bf  in
                    fwrite(bf.baseAddress, 1, bf.count, stdout);
                })
            }
        case "s":
            let s = LEccKeyChain.shared.getPrivateKeyInKeychain(curveType: ectool.curveType);
            let g = LEccKeyChain.shared.getPublicKeyInKeychain(curveType: ectool.curveType);
            if s != nil && g != nil {
                
                let dataOfSecure = try LTBase64.base64Decode(s!);
                printKey(key: dataOfSecure,title: ectool.ec.name)
                let msg =
    """
    ----
    privateKey:\(s!)
    publicKey:\(g!)
    export set \(EC_PUBKEY)=\(g!) \(EC_SECKEY)=\(s!)
    unset \(EC_PUBKEY) \(EC_SECKEY)
    """
                print(msg);
            }else{
                print("no key in keychain or read fail")
            }
        case "r":
            let strmsg = dicArg["m"] as! String?
            var dataMsg = strmsg?.data(using: .utf8);
            if(dataMsg == nil){
                dataMsg = readDataFromStdIn();
            }
            let s = RandomArt.randomArt(data: dataMsg!, title: nil , end: nil)
            print("\n\(s)");
            break
        default:
            Lprint(helpMsg)
        }
        
    }
    catch let e {
        //    print(e)
        redPrint(e)
        exit(1)
    }
    

    
}

main();

//let t = Test();
//t.test();
