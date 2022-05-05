//
//  number.swift
//  ECC-swift
//
//  Created by wei li on 2022/4/16.
//

import Foundation
import Accelerate
import libtommath
@inline(__always)func mp_iseven(_ a:UnsafePointer<mp_int>)->Bool{
    let mp = a.pointee
    return ((mp.used == 0) || ((mp.dp[0] & 1) == 0))
}
@inline(__always)func mp_isodd(_ a:UnsafePointer<mp_int>)->Bool{
    return !mp_iseven(a);
}


struct NU512{
    var value:mp_int
    init(){
        value = mp_int()
        _ = mp_init(&value)
    }
}

infix operator ===
extension NU512{
    var intValue :UInt32  {get {
        if value.used == 0 {
            return 0
        }
        return UInt32(value.dp[0] & 0xffffffff)
    }}
    
    func isNegtive() -> Bool{
        return (self.value.sign == MP_NEG)
    }
    mutating func setNeg(){
        withUnsafePointer(to: value) { a  in
            mp_neg(a , &value)
            
        }
    }
    
    static func  === (_ a:inout  NU512,_ b: NU512){
        _ = withUnsafePointer(to: b.value) { pb in
            mp_copy(pb , &a.value )
        }
    }
    
    static func  >>= (_  a:inout  NU512, _ rightShiftBits: Int32){
        _ = withUnsafePointer(to: a.value) { pa in
            mp_div_2d(pa, rightShiftBits , &a.value, nil)
        }
    }
    static func  <<= (_  a:inout  NU512, _ shift: Int32){
        _ = withUnsafePointer(to: a.value) { pa in
            mp_mul_2d(pa , shift, &a.value)
        }
    }
    
    static func  > (_  a:  NU512, _ b:  NU512) -> Bool{
        return withUnsafePointer(to: a.value) { pa  in
            return withUnsafePointer(to: b.value) { pb  in
                return mp_cmp(pa, pb) == MP_GT;
            }
        }
        
    }
    
    static func += (_ a:inout  NU512,_ b: NU512){
        _ = withUnsafePointer(to: a.value) { pa  in
            withUnsafePointer(to: b.value) { pb in
                mp_add(pa,pb, &a.value);
            }
        }
        
    }
    
    static func -= (_ a:inout  NU512,_ b: NU512){
        _ = withUnsafePointer(to: a.value) { pa  in
            withUnsafePointer(to: b.value) { pb in
                mp_sub(pa,pb, &a.value);
            }
        }
    }
    
    static func *= (_ a:inout  NU512,_ b: NU512){
        _ = withUnsafePointer(to: a.value) { pa  in
            withUnsafePointer(to: b.value) { pb in
                mp_mul(pa,pb, &a.value);
            }
        }
    }
    static func *= (_ a:inout  NU512,_ b: UInt64){
        _ = withUnsafePointer(to: a.value) { pa  in
            mp_mul_d(pa,b,&a.value)
        }
    }
    
    static func %= (_ a:inout  NU512,_ b: NU512) {
        _ = withUnsafePointer(to: a.value) { pa  in
            withUnsafePointer(to: b.value) { pb in
                mp_mod(pa,pb, &a.value);
            }
        }
    }
    
    
    
    static func - (_ a:  NU512,_ b: NU512) -> NU512{
        var z = NU512()
        _ = withUnsafePointer(to: a.value) { pa  in
            withUnsafePointer(to: b.value) { pb in
                mp_sub(pa,pb, &z.value);
            }
        }
        
        return z;
    }
    
    static prefix func - (_ a:  NU512) -> NU512{
        var z = NU512()
        _ = withUnsafePointer(to: a.value) { pa  in
            mp_neg(pa , &z.value)
        }
        return z;
    }
    
    static func + (_ a:  NU512,_ b:  NU512) -> NU512{
        var z = NU512()
        _ = withUnsafePointer(to: a.value) { pa  in
            withUnsafePointer(to: b.value) { pb in
                mp_add(pa,pb, &z.value);
            }
        }
        return z;
    }
    
    
    
    
    
    static func * (_ a:  NU512,_ b:  UInt32) -> NU512{
        var z = NU512()
       
        _ = withUnsafePointer(to: a.value) { pa  in
            mp_mul_d(pa , UInt64(b) , &z.value);
        }
        return z;
    }
    
    static func * (_ a:  NU512,_ b:  NU512) -> NU512{
        var z = NU512()
        _ = withUnsafePointer(to: a.value) { pa  in
            withUnsafePointer(to: b.value) { pb in
                mp_mul(pa , pb , &z.value)
            }
        }
        return z;
    }
    
    
    
    
//    static func % (_ a:  NU512,_ b:  UInt32) -> NU512{
//        var z = NU512()
//        _ = withUnsafePointer(to: a.value) { pa  in
//            mp_div_d(pa , UInt64(b), nil  , &z.value)
//        }
//        return z;
//
//    }
    
    static func % (_ a:  NU512,_ b:  NU512) -> NU512{
        var z = NU512()
        _ = withUnsafePointer(to: a.value) { pa  in
            withUnsafePointer(to: b.value) { pb in
                mp_div(pa , pb , nil , &z.value)
            }
        }
        return z;
        
    }
    
     
    
    static  func / (_ a:NU512,_ b:UInt32) -> NU512{
        var z = NU512()
        _ = withUnsafePointer(to: a.value) { pa  in
            mp_div_d(pa , UInt64(b) , &z.value , nil)
        }
        return z;
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
        let c = withUnsafePointer(to: self.value) { a -> Int32 in
            mp_copy(a , &result.value);
            return mp_cnt_lsb(a)
        }
        mp_rshd(&result.value,c);
         
    }
     
    
    
    
    
    func divide(_ b:NU512,result:inout NU512,remain:inout NU512){
        _ = withUnsafePointer(to: self.value) { pa  in
            withUnsafePointer(to: b.value) { pb  in
                mp_div(pa,pb,&result.value,&remain.value)
            }
        }
    }
    
    mutating func set(u32:UInt32){
        mp_set_u32(&value, u32)
    }
    init(u32:UInt32){
        self.init();
        _ = mp_init_u32(&value, u32)
    }
    
    func isOdd() -> Bool{
        return withUnsafePointer(to:self.value) { a  in
            return mp_isodd(a)
        }
    }
    
    func isZero() -> Bool{
        return self.value.used == 0
    }
    
    func printHex(_ msg:String = "", ln:Int = #line){
        print("line:\(ln) \(msg)",hexString())
    }
    
    
    
    
    func hexString() -> String{
        return withUnsafePointer(to:self.value) { a in
            var bf = [Int8](repeating: 0, count: 100);
            var w = 0
            _ = mp_to_radix(a , &bf , bf.count , &w , 0x10);
            
            return String(cString: bf).lowercased()
        }
         
    }
    
    func to32Bytes() -> [UInt8]{
        var r = [UInt8](repeating: 0, count: 32);
        withUnsafePointer(to: value) { a  in
//            mp_clamp(a)
            var w = 0
            _  = mp_to_ubin(a , &r, 32, &w);
            
            if w > 1 {
                // to little endian
                var left = 0, right = w - 1;
                while left < right{
                    let tmp = r[left];
                    r[left] = r[right];
                    r[right] = tmp;
                    left += 1
                    right -= 1
                }
            }
            
            
        }
         
        return r;
    }
    
    @inline(__always)static func == (_ x:NU512,_ y:NU512) -> Bool{
        return withUnsafePointer(to: x.value) { a  in
            withUnsafePointer(to: y.value) { b in
            return mp_cmp(a,b) == MP_EQ
        }
    }
    }
    
    @inline(__always) static  func == (_ x:NU512,_ y:UInt32) -> Bool{
        return  withUnsafePointer(to: x.value) { a in
            return mp_cmp_d(a , UInt64(y)) == MP_EQ
        }
    }
    
    
    @inline(__always) static func zeroN() -> NU512{
        var a = NU512.init()
        mp_zero(&a.value)
        return a
    }
    
    @inline(__always) static func oneN() -> NU512{
        
        var a = NU512();
        mp_set_u32(&a.value, 1);
        return a;
    }
    
    
    mutating func clear(){
        if(value.dp == nil){
            print("22")
            return;
        }
        mp_zero(&value)
        mp_clear(&value)
        value.dp = nil
        
        
    }
    
    
}
