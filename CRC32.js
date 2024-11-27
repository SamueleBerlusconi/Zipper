var CRC32 = Class.create();

/**
 * Class used to evaluate the CRC-32 checksum for a string or an array of bytes.
 *
 * @author Alex (original code)
 * @author Samuele Berlusconi (subsequent changes)
 * @see https://stackoverflow.com/a/18639999
 * @license Apache-2.0
 */
CRC32.prototype = {
    /**
     * Initialize the CRC-32 class by creating a calculated table based on the provided polynomial.
     * 
     * @param {Byte} [polynomial] Value used to compute the CRC table (Default: 0xEDB88320)
     */
    initialize: function(polynomial) {
        /**
         * Cache table containing all the results
         * of all values from 0 to 255 divided by
         * the CRC-32 polynom.
         * @type {number[]}
         */
        this._crc_table = null;

        /**
         * Polynomial value used to compute the CRC-32 value.
         * @type {Byte}
         */
        this.MAGIC_NUMBER = polynomial || 0xEDB88320;
    },

    /**
     * Calculate the CRC32 code for the provided argument.
     * @param {String|number[]} arg String or array of bytes to evaluate
     */
    evaluate: function(arg) {
        // Convert the parameter to array if it's a string
        var bytes = typeof arg === "string" ? this._strToByte(arg) : arg;

        var crcTable = this._crc_table || (this._crc_table = this._buildCRCTable());
        var crc = 0 ^ (-1);

        for (var i = 0; i < bytes.length; i++) {
            crc = (crc >>> 8) ^ crcTable[(crc ^ bytes[i]) & 0xFF];
        }

        return (crc ^ (-1)) >>> 0;
    },

    /**
     * Build a precompiled table with all the results of divisions between
     * bytes from 0 (00000000) to 255 (11111111) and the CRC-32 polynom.
     */
    _buildCRCTable: function() {
        var c;
        var crcTable = [];
        var polynomial = this.MAGIC_NUMBER;

        // Loop through each byte in the 32 bytes of CRC-32
        for (var n = 0; n < 32 * 8; n++) {
            c = n;

            // Each value c is composed of 8 bits, so we need to iterate 8 times per element
            for (var k = 0; k < 8; k++) {
                // The >>> (Unsigned Shift) operator shifts all the bits of c
                // one position to the right, adding a 0 bit on the left
                //
                // i.e. 101010 >>> 2 = 001010
                //
                // This is equivalent to dividing by 2^n
                // i.e. 101010 >>> 2 => (42) >>> (2) => 42/2^2 = 10 => 001010
                // Note that values are truncated (floored)
                //
                // So, in the following code, c is divided by 2 (2^1)
                //
                // c & 1 performs an AND operation on the byte, returning
                // 1 if the last bit of c is 1, 0 otherwise
                //
                // So if the last bit of c is 1, it is shifted right
                // and the XOR operation is performed, otherwise we just
                // shift the value to the right
                c = ((c & 1) ? (polynomial ^ (c >>> 1)) : (c >>> 1));
            }

            crcTable[n] = c;
        }

        return crcTable;
    },

    /**
     * Convert a string into the equivalent array of bytes.
     * @param {String} str String to convert into array
     * @returns Array of bytes
     */
    _strToByte: function(str) {
        var bytes = [];
        for (var i = 0; i < str.length; i++) {
            bytes.push(str.charCodeAt(i) & 0xFF);
        }
        return bytes;
    },

    type: "CRC32",
};
