/**
 * @typedef {object} FileData
 * @property {SysID} sys_id SysID of the attachment record
 * @property {String} name Filename of the current element
 * @property {number[]} data Array of bytes composing the file
 */

/**
 * Build a PKZip file containing one or more files directly from server side.
 *
 * @author Samuele Berlusconi (GitHub: @SamueleBerlusconi)
 * @see https://users.cs.jmu.edu/buchhofp/forensics/formats/pkzip.html#datadescriptor
 * @license Apache-2.0
 */
var Zipper = Class.create();
Zipper.prototype = {
    initialize: function() {

        /**
         * CRC-32 utility class used to hash the files.
         */
        this.CRC32 = new CRC32();

        /**
         * Maximum filename length by specific.
         */
        this.MAX_FILENAME_LENGTH = 256;

        /**
         * Array of files to include in the final archive.
         * @type {FileData[]}
         */
        this.files = [];

        /**
         * MIME type string identifying ZIP files.
         */
        this.MIME_TYPE = "application/zip";

        /**
         * Default archive extension use to postfix the filename.
         */
        this.ARCHIVE_EXTENSION = "zip";

        /**
         * Minimum version usable for PKZIP format (2.0).
         */
        this.PKZIP_VERSION = "\x14\x00";
    },

    /**
     * Add a file in the archive.
     * 
     * @param {SysID} attachment_id SysID of the attachment in the Attachment [sys_attachment] table
     */
    add: function(attachment_id) {
        // Get the attachment record
        var grAttachment = new GlideRecord("sys_attachment");
        var exists = grAttachment.get(attachment_id);

        if (!exists) throw new Error("No record found on the sys_attachment table with the provided SysID");

        // Parse the file from the table
        var file = {};
        file.sys_id = grAttachment.getValue("sys_id");
        file.name = grAttachment.getValue("file_name").substring(0, this.MAX_FILENAME_LENGTH - 1);
        file.data = this._binToString(new GlideSysAttachment().getBytes(grAttachment));

        this.files.push(file);
    },

    /**
     * Write the ZIP archive as a attachment in the target record.
     * 
     * @param {String} table Name of the table where save the file
     * @param {SysID} record SysID of the record that will contains the attachment
     * @param {String} filename Name of the exported archive (automatically include the extension)
     * @returns {SysID} SysID of the created attachment record
     */
    write: function(table, record, filename) {
        // Validate parameters
        if (gs.nil(table) || !gs.tableExists(table)) throw new Error("Invalid parameter: the 'table' parameter must be an existing table name");
        if (gs.nil(record) || !GlideStringUtil.isEligibleSysID(record)) throw new Error("Invalid parameter: the 'record' parameter must be a valid record SysID");
        if (gs.nil(filename)) throw new Error("Invalid parameter: the 'filename' parameter is not defined");

        // Parse the filename
        if (!filename.endsWith("." + this.ARCHIVE_EXTENSION)) filename += "." + this.ARCHIVE_EXTENSION;

        // Set the date used in the local headers
        this.date = new Date();
        this._zipDate = {};
        this._zipDate.date = this._getZipDate(this.date);
        this._zipDate.time = this._getZipTime(this.date);

        /**
         * Binary string containing the archive data.
         */
        var data = "";

        /**
         * Binary string containing the central directory of the archive
         */
        var directory = "";

        /**
         * Current position of the cursor.
         */
        var offset = 0;

        // For every file create the respective header than append the file data
        for (var i = 0; i < this.files.length; i++) {
            var file = this.files[i];

            data += this._header(file); // Create local header for the file
            data += file.data; // Add binary data of the file

            directory += this._directory(file, offset); // Create Central Directory entry for this file

            offset += data.length; // Update cursor position
        }

        // Add the Central Directory entries and its end to the archive
        data += directory; // First byte of the directory is at position "offset"
        data += this._eoDirectory(this.files.length, directory.length, directory);

        // Get the target record (if exists)
        var target = new GlideRecord(table);
        var exists = target.get(record);

        if (!exists) throw new Error("No record with SysID " + record + " found on table " + table);

        // Write the zip file as attachment
        var attachment = new GlideSysAttachment();
        // return attachment.write(target, filename, this.MIME_TYPE, data); // Will not works, see below

        throw new Error("Unsupported Platform: ServiceNow doesn't support writing bytes as Unicode, it will transform them to UTF-8, breaking the ZIP structure");
        // See: https://www.servicenow.com/community/developer-forum/any-get-glidesysattachment-write-to-work-for-binary-files-while/m-p/1601628/page/3
    },

    /**
     * Build the local header for the provided file.
     * 
     * @param {FileData} file File for which build the local header
     */
    _header: function(file) {
        /**
         * Initial "PK" local header signature for PKZIP format.
         */
        var PKZIP_LOCAL_SIGNATURE = "\x50\x4b\x03\x04";

        /**
         * Byte header for the current file.
         */
        var header = "";

        // Prepare the file signature
        header += PKZIP_LOCAL_SIGNATURE; // Local file header signature
        header += this.PKZIP_VERSION; // Version needed to extract
        header += "\x00\x00"; // General purpose bit flag (always empty)
        header += "\x00\x00"; // Compression method (0 = no compression)

        // Timestamp ZIP file
        header += this._intToBytes(this._zipDate.time, 2); // File last modification time
        header += this._intToBytes(this._zipDate.date, 2); // File last modification date

        // CRC-32
        header += this._intToBytes(this.CRC32.evaluate(file.data), 4);

        // Compressed size e Uncompressed size
        header += this._intToBytes(file.data.length, 4);
        header += this._intToBytes(file.data.length, 4); // Same value as above as the file is uncompressed

        // Filename length
        header += this._intToBytes(file.name.length, 2);

        // Extra field length (set to 0 as the field is not used)
        header += "\x00\x00";

        // Filename (max length: 256 chars)
        header += file.name;

        return header;
    },

    /**
     * Build a Central Directory entry for the given file.
     * 
     * @param {FileData} file File for which build the central directory
     * @param {number} Position of the locla header for the 'file' parameter
     */
    _directory: function(file, offset) {
        /**
         * Initial "PK" Central Directory header signature for PKZIP format.
         */
        var PKZIP_CD_SIGNATURE = "\x50\x4B\x01\x02";

        /**
         * Byte entry for the current file in the Central Directory.
         */
        var directory = "";

        // Firma del "central directory header"
        directory += PKZIP_CD_SIGNATURE; // Central file header signature
        directory += this.PKZIP_VERSION; // Version made by
        directory += this.PKZIP_VERSION; // Version needed to extract
        directory += "\x00\x00"; // General purpose bit flag
        directory += "\x00\x00"; // Compression method (0 = no compression)

        // Timestamp ZIP file
        directory += this._intToBytes(this._zipDate.time, 2); // File last modification time
        directory += this._intToBytes(this._zipDate.date, 2); // File last modification date

        // CRC-32
        directory += this._intToBytes(this.CRC32.evaluate(file.data), 4);

        // Compressed size e Uncompressed size
        directory += this._intToBytes(file.data.length, 4);
        directory += this._intToBytes(file.data.length, 4); // Same value as above as the file is uncompressed

        // Filename length
        directory += this._intToBytes(file.name.length, 2);

        directory += "\x00\x00"; // Extra field length
        directory += "\x00\x00"; // File comment length
        directory += "\x00\x00"; // Disk number start
        directory += "\x00\x00"; // Internal file attributes
        directory += "\x00\x00\x00\x00"; // External file attributes

        // Position of the local header for this file relatively to the current central directory
        directory += this._intToBytes(offset, 4);

        // Filename (max length: 256 chars)
        directory += file.name;

        return directory;
    },

    /**
     * Build the conclusive part of the archive.
     * 
     * @param {number} entries Number of files in the archive
     * @param {number} size Size of the Central Directory header
     * @param {number} offset Position of the first Byte of the Central Directory
     */
    _eoDirectory: function(entries, size, offset) {
        /**
         * Initial "PK" Central Directory end header signature for PKZIP format.
         */
        var PKZIP_EOCD_SIGNATURE = "\x50\x4B\x05\x06";

        /**
         * Byte header for the current element.
         */
        var eocd = "";

        eocd += PKZIP_EOCD_SIGNATURE; // End of central directory signature
        eocd += "\x00\x00"; // Number of this disk
        eocd += "\x00\x00"; // Disk where central directory starts
        eocd += this._intToBytes(entries, 2); // Total number of entries in central directory
        eocd += this._intToBytes(entries, 2); // Total number of entries across all disks
        eocd += this._intToBytes(size, 4); // Size of central directory
        eocd += this._intToBytes(offset, 4); // Offset of start of central directory
        eocd += "\x00\x00"; // Comment length

        return eocd;
    },

    /**
     * Convert a Date object into the PKZIP time format.
     * 
     * @param {Date} date Date from which extract the timestamp
     */
    _getZipTime: function(date) {
        // Get the hour, minutes, and seconds components
        var hours = date.getHours(); // 0-23
        var minutes = date.getMinutes(); // 0-59
        var seconds = date.getSeconds(); // 0-59

        // ZIP uses seconds divided by 2 (0-29)
        var zipSeconds = Math.floor(seconds / 2);

        // Encode the time (16 bits): hours in bits 11-15, minutes in bits 5-10, seconds/2 in bits 0-4
        return (hours << 11) | (minutes << 5) | zipSeconds;
    },

    /**
     * Convert a Date object into the PKZIP date format.
     * 
     * @param {Date} date Date from which extract the datestamp
     */
    _getZipDate: function(date) {
        // Get the year, month, and day components
        var year = date.getFullYear(); // For example: 2024
        var month = date.getMonth() + 1; // Months in JavaScript are 0-11, so +1
        var day = date.getDate(); // Day of the month

        // ZIP uses the year starting from 1980
        var zipYear = year - 1980;

        // Encode the date (16 bits): year in bits 9-15, month in bits 5-8, day in bits 0-4
        return (zipYear << 9) | (month << 5) | day;
    },

    /**
     * Convert an array of bytes into the equivalent string.
     * 
     * @param {number[]} Byte array to convert
     * @returns {String} Converted bytes
     */
    _binToString: function(array) {
        // This implementation ensures that the resulting string represents raw bytes 
        // without being affected by UTF-8 encoding or Unicode interpretation. 
        // Unlike String.fromCharCode applied to the entire array, which may encode 
        // certain values as multi-byte UTF-8 characters, this approach builds the 
        // string byte-by-byte to preserve the exact binary representation.

        var sbytes = "";

        for (var j = 0; j < array.length; j++) {
            sbytes += String.fromCharCode(array[j] & 0xff); // Mask to ensure valid byte [0-127]
        }

        return sbytes;
    },

    /**
     * Convert an integer value into the equivalent byte string.
     * 
     * @param {number} value Number to convert into byte string
     * @param {number} byteCount Number of bytes used to represent the integer value
     * @returns {String} Byte string representing the value using the provided amount of bytes
     */
    _intToBytes: function(value, byteCount) {
        var bytes = [];
        for (var i = 0; i < byteCount; i++) {
            bytes.push(value & 0xff); // Take the last byte (8 bit)
            value >>= 8; // Move the next 8 bit into the next byte
        }

        // Pad with zeros if needed
        while (bytes.length < byteCount) bytes.push(0);

        return this._binToString(bytes);
    },

    type: "Zipper"
};
