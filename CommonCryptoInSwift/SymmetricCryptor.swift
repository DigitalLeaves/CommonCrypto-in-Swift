//
//  CommonCryptoManager.swift
//  CommonCryptoInSwift
//
//  Created by Ignacio Nieto Carvajal on 9/8/15.
//  Copyright © 2015 Ignacio Nieto Carvajal. All rights reserved.
//

import UIKit

class SymmetricCryptor: NSObject {
    // properties
    var algorithm: CCAlgorithm      // Algorithm
    var options: CCOptions          // Options (i.e: kCCOptionECBMode + kCCOptionPKCS7Padding)
    var iv: NSData?                 // Initialization Vector

    init(algorithm: Int, options: Int) {
        self.algorithm = CCAlgorithm(algorithm)
        self.options = CCOptions(options)
    }
    
    convenience init(algorithm: Int, options: Int, iv: String, encoding: UInt = NSUTF8StringEncoding) {
        self.init(algorithm: algorithm, options: options)
        self.iv = iv.dataUsingEncoding(encoding)
    }
    
    func crypt(string: String, key: String) {
        cryptoOperation(string, key: key, operation: CCOperation(kCCEncrypt))
    }
    
    func decrypt(string: String, key: String) {
        cryptoOperation(string, key: key, operation: CCOperation(kCCDecrypt))
    }
    
    internal func cryptoOperation(string: String, key: String, operation: CCOperation) -> NSData {
        // Data parameters
        let keyData: NSData! = key.dataUsingEncoding(NSUTF8StringEncoding, allowLossyConversion: false)!
        let keyBytes         = UnsafePointer<Void>(keyData.bytes)
        let keyLength        = size_t(kCCKeySize3DES)
        let stringAsData     = string.dataUsingEncoding(NSUTF8StringEncoding)!
        let dataLength       = Int(stringAsData.length)
        let dataBytes        = UnsafePointer<Void>(stringAsData.bytes)
        let bufferData       = NSMutableData(length: Int(dataLength) + kCCBlockSize3DES)!
        let bufferPointer    = UnsafeMutablePointer<Void>(bufferData.mutableBytes)
        let bufferLength     = size_t(bufferData.length)
        let noIV = UnsafePointer<Void>(iv?.bytes ?? nil)
        var bytesDecrypted = Int(0)
        let cryptStatus = CCCrypt(
            operation,          // Operation
            algorithm,          // Algorithm
            options,            // Options (ECB + PKCS7 Padding)
            keyBytes,           // key data
            keyLength,          // key length
            noIV,               // 0 (null) IV, as we are using ECB
            dataBytes,          // input data
            dataLength,         // input length
            bufferPointer,      // output buffer
            bufferLength,       // output buffer length
            &bytesDecrypted)  // output bytes decrypted real length
        if UInt32(cryptStatus) == UInt32(kCCSuccess) {
            bufferData.length = bytesDecrypted // Adjust buffer size to real bytes
            print("Decyphered: \(bufferData as NSData)\n")
            if let asstring = NSString(data: bufferData as NSData, encoding: NSUTF8StringEncoding) { print("As string: \(asstring)\n") }
            return bufferData as NSData
        } else {
            print("Error: \(cryptStatus)\n")
            return NSData()
        }
    }
}
