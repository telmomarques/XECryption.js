/**
 * OOP terminology was used to document this script.
 */

/*******************************************************************************
 * Namespace definition
 ******************************************************************************/
var XECryptionJS = {};
XECryptionJS.XECryption = {};
//******************************************************************************

/*******************************************************************************
 * Class Encryptor
 * Constructor
 * Encrpyts a plain text string using the XECryption algorithm
 * @param {String} text Plain text to encrypt
 * @param {String} password Encryption password
 ******************************************************************************/
XECryptionJS.XECryption.Encryptor = function(text)
{
    this.encryptedLetters = [];
    this.text = text;
};

/**
 * Perform encryption
 * @param {String} Encryption password
 * @returns {String} Encrypted text
 */
XECryptionJS.XECryption.Encryptor.prototype.encrypt = function(password)
{
    var encryptedLetter = null;
    var encryptedText = "";
    
    var passwordValue = XECryptionJS.XECryption.Utils.passwordValueFromString(password);
    
    for(var i=0; i<this.text.length; i++)
    {
        encryptedLetter = XECryptionJS.XECryption.EncryptedLetter.fromChar(this.text.charAt(i), passwordValue);
        encryptedText += "."+encryptedLetter.getN1()+"."+encryptedLetter.getN2()+"."+encryptedLetter.getN3();
    }
    
    return encryptedText;
};
//******************************************************************************


/*******************************************************************************
 * Class Decryptor
 * Constructor
 * Decrypts text encrypted using the XECryption algorithm
 * @param {String} encryptedText Encrypted text
 ******************************************************************************/
XECryptionJS.XECryption.Decryptor = function(encryptedText)
{
    this.encryptedLetters = [];
    var encryptedLetterBuffer = [];
    this.maximumPasswordValue = null;
    this.currentPasswordValue = null;
    
    encryptedText = encryptedText.substr(1).replace(/(\r\n|\n|\r)/gm,"");
    var encryptedTextSplittedByPeriod = encryptedText.split(".");
    
    for(var i=0; i<encryptedTextSplittedByPeriod.length; i++)
    {
        encryptedLetterBuffer[i%3] = encryptedTextSplittedByPeriod[i];
        if(i%3 === 2)
        {
            var encryptedLetter = new XECryptionJS.XECryption.EncryptedLetter(parseInt(encryptedLetterBuffer[0]), parseInt(encryptedLetterBuffer[1]), parseInt(encryptedLetterBuffer[2]));
            this.encryptedLetters.push(encryptedLetter);
            if(this.maximumPasswordValue === null || encryptedLetter.getSum() < this.maximumPasswordValue)
            {
                this.maximumPasswordValue = encryptedLetter.getSum();
            }
        }
    }

};

/**
 * Decryption Result Anomymous Class
 * @name DecryptionResult
 * @function
 * @param {String} decryptedText Decrypted Text
 * @param {Number} passwordValue The password value used for this decryption instance
 */

/**
 * Performs decryption with optimized password.
 * Each time this function is called a different - optimized - password value
 * is used.
 * @returns {DecryptionResult} The Decryption result
 */
XECryptionJS.XECryption.Decryptor.prototype.decryptUsingNextPasswordValue = function()
{
    var possiblePasswordValue = this.currentPasswordValue;
    if(possiblePasswordValue === null)
    {
        this.currentPasswordValue = 0;
        possiblePasswordValue = this.getPossiblePasswordValueByAnalyzingTextFrequency();
    }
    else
    {
        this.currentPasswordValue++;
    }
    
    return this.decrypt(possiblePasswordValue);
};


/**
 * Performs decryption
 * @param {type} passwordValue The password value for decryption
 * @returns {DecryptionResult} The Decryption result
 */
XECryptionJS.XECryption.Decryptor.prototype.decrypt = function(passwordValue)
{
    var decryptedText = "";
    
    for(var i=0; i<this.encryptedLetters.length; i++)
    {
        decryptedText += String.fromCharCode(this.encryptedLetters[i].getSum()-passwordValue);
    }
    
    return {decryptedText: decryptedText, passwordValue: passwordValue};
};

/**
 * Tries to optimize the password for decryption by analyzing text frequency
 * @returns {Number} Possible decryption password
 */
XECryptionJS.XECryption.Decryptor.prototype.getPossiblePasswordValueByAnalyzingTextFrequency = function()
{
    var encryptedLetterFrequency = [];
    var mostCommonEncryptedAsciiValue = 0;
    if(this.encryptedLetters.length > 0)
    {
        mostCommonEncryptedAsciiValue = this.encryptedLetters[0].getSum();
    }
    var asciiSpaceValue = 32;
    
    for(var i=0; i<this.encryptedLetters.length; i++)
    {
        var encryptedAsciiValue = this.encryptedLetters[i].getSum();
        if(encryptedLetterFrequency[encryptedAsciiValue] === undefined)
        {
            encryptedLetterFrequency[encryptedAsciiValue] = 1;
        }
        else
        {
            encryptedLetterFrequency[encryptedAsciiValue]++;
        }
    }
    
    for(var arrayKey in encryptedLetterFrequency)
    {
        if(encryptedLetterFrequency[arrayKey] > encryptedLetterFrequency[mostCommonEncryptedAsciiValue])
        {
            mostCommonEncryptedAsciiValue = arrayKey;
        }
    }
    
    return mostCommonEncryptedAsciiValue - asciiSpaceValue;
};
//******************************************************************************


/**
 * EncryptedLetter Class
 * Constructor
 * Represents a single Letter in its encrypted form
 * @param {Number} n1 First number of encpryted letter
 * @param {Number} n2 Second number of encpryted letter
 * @param {Number} n3 Third number of encpryted letter
 */
XECryptionJS.XECryption.EncryptedLetter = function(n1, n2, n3)
{
    this.n1 = n1;
    this.n2 = n2;
    this.n3 = n3;
    this.sum = n1+n2+n3;
};

/**
 * Encrypts a plain text letter using XECryption algorithm
 * @param {String} char the letter to encrypt
 * @param {Number} passwordValue Password value for encryption
 * @returns {XECryptionJS.XECryption.EncryptedLetter} Encrypted letter
 */
XECryptionJS.XECryption.EncryptedLetter.fromChar = function(char, passwordValue)
{
    var charAsciiValue = char.charCodeAt(0);
    
    var n1 = Math.floor((charAsciiValue/3) + ((Math.random()*10)+1));
    var n2 = Math.floor((charAsciiValue/3) + ((Math.random()*10)+1));
    var n3 = charAsciiValue -(n1+n2)+passwordValue;
    
    return new XECryptionJS.XECryption.EncryptedLetter(n1, n2, n3);
};

/**
 * Get the sum of the parts of the encripted letter (Encrypted ASCII value)
 * @returns {Number}
 */
XECryptionJS.XECryption.EncryptedLetter.prototype.getSum = function()
{
    return this.sum;
};

XECryptionJS.XECryption.EncryptedLetter.prototype.getN1 = function()
{
    return this.n1;
};

XECryptionJS.XECryption.EncryptedLetter.prototype.getN2 = function()
{
    return this.n2;
};

XECryptionJS.XECryption.EncryptedLetter.prototype.getN3 = function()
{
    return this.n3;
};
//******************************************************************************

/*******************************************************************************
 * Class Utils
 * Constructor
 * Holds utility functions
 ******************************************************************************/
XECryptionJS.XECryption.Utils = {};
/**
 * Returns ASCII value to use as a password for a given string
 * @param {String} Password
 * @returns {Number} ASCII password value
 */
XECryptionJS.XECryption.Utils.passwordValueFromString = function(password)
{
    var passwordValue = 0;
    for(var i=0; i<password.length; i++)
    {
        passwordValue += password.charCodeAt(i);
    }
    
    return passwordValue;
};
//******************************************************************************