//
//  number.swift
//  ECC-swift
//
//  Created by wei li on 2022/4/16.
//

import Foundation
import Accelerate

extension EC.NU512{
    var intValue :UInt32  {get {return v.0[0]}}
    
    func isNegtive() -> Bool{
        return (self.v.3[3] & 0x08000000) > 0
    }
    
    static func - (_ a:  NU512,_ b: NU512) -> NU512{
        return withUnsafePointer(to: a) { A in
            return withUnsafePointer(to: b) { B in
                var z = zeroN();
                vU512Sub(A , B , &z);
                return z;
            }
        }
    }
    
    static func + (_ a:  NU512,_ b:  NU512) -> NU512{
        return withUnsafePointer(to: a) { A in
            return withUnsafePointer(to: b) { B in
                var z = NU512();
                vU512Add(A , B , &z)
                return z;
            }
        }
    }
    static func += (_ a: inout NU512,_ b:  NU512) {
        withUnsafeMutablePointer(to: &a) { A in
            withUnsafePointer(to: b) { B in
                vU512Add(A , B , A)
            }
        }
    }
    
    
    
    
    static func * (_ a:  NU512,_ b:  UInt32) -> NU512{
        let b512 = NU512(u32: b)
        return withUnsafePointer(to: a) { A in
            return withUnsafePointer(to: b512) { B in
                var z = NU512();
                vU512HalfMultiply(A , B , &z)
                return z;
            }
        }
    }
    
    static func * (_ a:  NU512,_ b:  NU512) -> NU512{
        let b512 = b
        return withUnsafePointer(to: a) { A in
            return withUnsafePointer(to: b512) { B in
                var z = NU512();
                vU512HalfMultiply(A , B , &z)
                
                
                return z;
            }
        }
    }
    
    
    
    
    static func % (_ a:  NU512,_ b:  UInt32) -> NU512{
        
        let b2 = NU512(u32: b);
        
        return withUnsafePointer(to: a) { A in
            return withUnsafePointer(to: b2) { B in
                var z = zeroN();
                vU512Mod(A , B, &z);
                return z;
            }
        }
        
    }
    
    static func % (_ a:  NU512,_ b:  NU512) -> NU512{
        return withUnsafePointer(to: a) { A in
            return withUnsafePointer(to: b) { B in
                var z = zeroN();
                vU512Mod(A , B, &z);
                return z;
            }
        }
        
    }
    
    
    
    
    
    static prefix func - (_ a:NU512) -> NU512{
        return withUnsafePointer(to: a) { A in
            var z = zeroN();
            vU512Neg(A , &z)
            return z;
        }
    }
    
    
    static  func / (_ a:NU512,_ b:UInt32) -> NU512{
        let b512 = NU512(u32: b);
        return withUnsafePointer(to: a) { A in
           return  withUnsafePointer(to: b512) { B  in
               var z = zeroN();
               var zz = zeroN();
               vU512Divide(A , B , &z, &zz);
               return z;
            }
            
        }
    }
    
    
    func countRightZero(u32:UInt32) -> Int{
        if u32 == 0{
            return 32;
        }
        var C = ((u32 &- 1) ^ u32);
        
        var countOf1 = 0;
        while C != 0{
            C &= C - 1;
            countOf1 += 1;
        }
        
        return countOf1 - 1;
    }
    
   
    
    func  removeAllRightZero(result:inout NU512, zeroBitCount:inout Int){
        var tmp = [UInt32](repeating: 0, count: 16);
        for i in 0..<16{
            let m = i / 4;
            let n = i % 4;
            switch m  {
            case 0:
                tmp[i] = self.v.0[n];
            case 1:
                tmp[i] = self.v.1[n];
            case 2:
                tmp[i] = self.v.2[n];
            case 3:
                tmp[i] = self.v.3[n];
                
            default:
                break
            }
            
        }
        defer {
            memset(&tmp, 0, 64);
        }
        
        var bitcount = 0;
        var bytecount = 0;
        
        var i = 0;
        while i < 16 && tmp[i] == 0{
            i += 1;
            bitcount +=  32;
            bytecount += 4;
        }
        
        let bitShift = countRightZero(u32: tmp[i]);
        zeroBitCount = bitcount + bitShift
        
        if(bytecount > 0){
            for i in bytecount..<16{
                tmp[i - bytecount] = tmp[i];
            }
        }
        
        if bitShift > 0{
            
            let LeftBits = 32 - bitShift
            let maskR = UInt32.max >> (LeftBits) ;
            
            for i in 0..<16{
                let V = tmp[i];
                let VNxt = i < 16 ? tmp[i] : 0;
                tmp[i] = (V >> bitShift) | (VNxt & maskR) << LeftBits
            }
        }
        
        
        
        
        for i in 0..<16{
            let m = i / 4;
            let n = i % 4;
            switch m  {
            case 0:
                result.v.0[n] = tmp[i]
            case 1:
                result.v.1[n] = tmp[i]
            case 2:
                result.v.2[n] = tmp[i]
            case 3:
                result.v.3[n] = tmp[i]
                
            default:
                break
            }
            
        }
         
    }
     
    
    
    
    
    func divide(_ b:NU512,result:inout NU512,remain:inout NU512){
        let a = self;
        withUnsafePointer(to: a) { A in
            withUnsafePointer(to: b) { B in
                vU512Divide(A, B, &result, &remain);
            }
        }
    }
    
    init(u32:UInt32){
        self.init();
        self.v.0[0] = u32;
    }
    
    func printHex(ln:Int = #line){
        print("line:\(ln)",hexString())
    }
    
    
    func highHexString() -> String{
        let n = self;
        var s = String(format: "%08x", n.v.2[0]);
        s = String(format: "%08x", n.v.2[1]) + s
        s = String(format: "%08x", n.v.2[2]) + s
        s = String(format: "%08x", n.v.2[3]) + s
        s = String(format: "%08x", n.v.3[0]) + s
        s = String(format: "%08x", n.v.3[1]) + s
        s = String(format: "%08x", n.v.3[2]) + s
        s = String(format: "%08x", n.v.3[3]) + s
//        s = String(format: " %08x", n.v.2[0]) + s
//        s = String(format: " %08x", n.v.2[1]) + s
//        s = String(format: " %08x", n.v.2[2]) + s
//        s = String(format: " %08x", n.v.2[3]) + s
//        s = String(format: " %08x", n.v.3[0]) + s
//        s = String(format: " %08x", n.v.3[1]) + s
//        s = String(format: " %08x", n.v.3[2]) + s
//        s = String(format: " %08x", n.v.3[3]) + s
        
//        print(s);
         
         return s;
    }
    
    func hexString() -> String{
        let n = self;
        var s = String(format: "%08x", n.v.0[0]);
        s = String(format: "%08x", n.v.0[1]) + s
        s = String(format: "%08x", n.v.0[2]) + s
        s = String(format: "%08x", n.v.0[3]) + s
        s = String(format: "%08x", n.v.1[0]) + s
        s = String(format: "%08x", n.v.1[1]) + s
        s = String(format: "%08x", n.v.1[2]) + s
        s = String(format: "%08x", n.v.1[3]) + s
//        s = String(format: " %08x", n.v.2[0]) + s
//        s = String(format: " %08x", n.v.2[1]) + s
//        s = String(format: " %08x", n.v.2[2]) + s
//        s = String(format: " %08x", n.v.2[3]) + s
//        s = String(format: " %08x", n.v.3[0]) + s
//        s = String(format: " %08x", n.v.3[1]) + s
//        s = String(format: " %08x", n.v.3[2]) + s
//        s = String(format: " %08x", n.v.3[3]) + s
        
//        print(s);
         
         return s;
    }
    
    
}
