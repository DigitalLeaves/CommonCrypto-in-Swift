//
//  ViewController.swift
//  CommonCryptoInSwift
//
//  Created by Ignacio Nieto Carvajal on 9/8/15.
//  Copyright © 2015 Ignacio Nieto Carvajal. All rights reserved.
//

import UIKit

class ViewController: UIViewController {
    // outlets && buttons
    @IBOutlet weak var clearTextView: UITextView!
    @IBOutlet weak var cypheredTextView: UITextView!
    @IBOutlet weak var symmetricKeyLabel: UITextField!
    
    @IBOutlet weak var desButton: UIButton!
    @IBOutlet weak var tripledesButton: UIButton!
    @IBOutlet weak var rc4Button: UIButton!
    @IBOutlet weak var rc2Button: UIButton!
    @IBOutlet weak var aesButton: UIButton!
    @IBOutlet weak var pkcs7Button: UIButton!
    @IBOutlet weak var ebcButton: UIButton!
    
    // data
    var selectedAlgorithm: SymmetricCryptorAlgorithm = .DES
    var pkcs7Padding = false
    var useEcbMode = false
    var clearText: String = "Sed posuere consectetur est at lobortis. Donec id elit non mi porta gravida at eget metus. Vestibulum id ligula porta felis euismod semper. Lorem ipsum dolor sit amet, consectetur adipiscing elit. Morbi leo risus, porta ac consectetur ac, vestibulum at eros. Vivamus sagittis lacus vel augue laoreet rutrum faucibus dolor auctor."
    var cypherText: NSData?
    var iv: NSData?
    
    override func viewDidLoad() {
        super.viewDidLoad()
        // Do any additional setup after loading the view, typically from a nib.
    }
    
    override func viewWillAppear(animated: Bool) {
        super.viewWillAppear(animated)
        clearTextView.text = clearText
    }

    override func didReceiveMemoryWarning() {
        super.didReceiveMemoryWarning()
        // Dispose of any resources that can be recreated.
    }

    // MARK: - Button actions
    @IBAction func generateKey(sender: UIButton!) {
        let key = SymmetricCryptor.randomStringOfLength(selectedAlgorithm.requiredKeySize())
        self.symmetricKeyLabel.text = key
    }
    
    @IBAction func cypher(sender: AnyObject) {
        // validity checks
        if clearTextView.text?.characters.count < 1 {
            showAlertWithMessage("Please enter a valid clear text.")
            return
        } else { clearText = clearTextView.text! }
        // build cryptor
        let options = getCypheringOptions()
        let cypher = SymmetricCryptor(algorithm: selectedAlgorithm, options: options)
        if !useEcbMode { // IV needed if not in ECB mode
            setIV(cypher)
        }
        if symmetricKeyLabel.text?.characters.count < 1 { generateKey(nil) }
        // perform cyphering
        do {
            cypherText = try cypher.crypt(string: clearText, key: symmetricKeyLabel.text!)
            if let cypheredString = NSString(data: cypherText!, encoding: NSUTF8StringEncoding) {
                cypheredTextView.text = cypheredString as String
            } else {
                cypheredTextView.text = "(Result not printable as string): \(cypherText)"
            }
            clearTextView.text = ""
        } catch {
            self.showAlertWithMessage("Unable to perform cyphering on given text. \(error). Try enabling PKCS7 padding.")
        }
    }
    
    @IBAction func decypher(sender: AnyObject) {
        // validity checks
        if cypherText == nil {
            showAlertWithMessage("No cypher text to decypher")
            return
        } else { clearText = clearTextView.text! }
        // build cryptor
        let options = getCypheringOptions()
        let cypher = SymmetricCryptor(algorithm: selectedAlgorithm, options: options)
        if !useEcbMode { // IV needed if not in ECB mode
            setIV(cypher)
        }
        if symmetricKeyLabel.text?.characters.count < 1 { generateKey(nil) }
        // perform cyphering
        do {
            let clearData = try cypher.decrypt(cypherText!, key: symmetricKeyLabel.text!)
            if let clearDataAsString = NSString(data: clearData, encoding: NSUTF8StringEncoding) {
                clearText = clearDataAsString as String
                clearTextView.text = clearText
                cypherText = nil
            } else { clearTextView.text = "(Unable to generate a valid response string, probably wrong key or parameters, showing as NSData instead): \(clearData)" }
            cypheredTextView.text = ""
        } catch {
            self.showAlertWithMessage("Unable to perform decyphering on given text. \(error)")
        }

    }
    
    @IBAction func selectDESAlgorithm(sender: UIButton) {
        selectedAlgorithm = .DES
        selectAlgorithmButton(sender)
    }
    
    @IBAction func select3DESAlgorithm(sender: UIButton) {
        selectedAlgorithm = .TRIPLEDES
        selectAlgorithmButton(sender)
    }
    
    @IBAction func selectRC4Algorithm(sender: UIButton) {
        selectedAlgorithm = .RC4_128
        selectAlgorithmButton(sender)
    }
    
    @IBAction func selectRC2Algorithm(sender: UIButton) {
        selectedAlgorithm = .RC2_128
        selectAlgorithmButton(sender)
    }
    
    @IBAction func visuallySelectAESAlgorithm(sender: UIButton) {
        selectedAlgorithm = .AES_128
        selectAlgorithmButton(sender)
    }
    
    @IBAction func pkcs7ButtonTouched(sender: UIButton) {
        self.pkcs7Padding = !self.pkcs7Padding
        UIView.animateWithDuration(0.5) { () -> Void in
            self.pkcs7Button.alpha = self.pkcs7Padding ? 1.0 : 0.20
        }
    }
    
    @IBAction func ebcButtonTouched(sender: UIButton) {
        self.useEcbMode = !self.useEcbMode
        UIView.animateWithDuration(0.5) { () -> Void in
            self.ebcButton.alpha = self.useEcbMode ? 1.0 : 0.20
        }
    }
    
    private func selectAlgorithmButton(button: UIButton) {
        self.symmetricKeyLabel.text = ""
        var allButtons: [UIButton] = [desButton, tripledesButton, rc4Button, rc2Button, aesButton]
        if let index = allButtons.indexOf(button) {
            allButtons.removeAtIndex(index)
            UIView.animateWithDuration(0.5, animations: { () -> Void in
                for buttonToFade in allButtons { buttonToFade.alpha = 0.20 }
                button.alpha = 1.0
            })
        }
    }
    
    func setIV(cypher: SymmetricCryptor) {
        if iv == nil {
            cypher.setRandomIV()
            iv = cypher.iv
        } else { cypher.iv = iv! }
    }
    
    func getCypheringOptions() -> Int {
        // build cyphering options
        var options = 0
        if self.pkcs7Padding { options |= kCCOptionPKCS7Padding }
        if self.useEcbMode { options |= kCCOptionECBMode }
        return options
    }

    // MARK: - UIViewController alerts options.
    func showAlertWithMessage(msg: String, completion: (() -> Void)? = nil) {
        let alert = UIAlertController(title: nil, message: msg, preferredStyle: .Alert)
        alert.addAction(UIAlertAction(title: "Ok", style: .Default, handler: nil))
        self.presentViewController(alert, animated: true, completion: completion)
    }
    
    override func touchesBegan(touches: Set<UITouch>, withEvent event: UIEvent?) {
        self.view.endEditing(true)
    }
}

