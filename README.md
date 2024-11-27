# Zipper
Implementation of the ZIP standard for storing (without compression) multiple attachments directly from Server code in ServiceNow.

The structure is implemented using the following documentations: [The structure of a PKZip file](https://users.cs.jmu.edu/buchhofp/forensics/formats/pkzip.html#datadescriptor)

# How to install
Create two new Script Includes, and copy-paste the JS files in this repository:
- CRC32: Copy the content of the CRC32.js file
- Zipper: Copy the content of the Zipper.js file

Consider that the two scripts were developed in the *Global* scope in a Washington instance.

# How to use
After instancing the *Zipper* class, use the `add` method to push existing attachments into the package and finally save the resulting archive into an existing record with `write`.

```javascript

var zipper = new Zipper();
zipper.add(ATTACHMENT_ID); // Add a single file to the archive
zipper.write(TARGET_TABLE, TARGET_ID, "Archive Filename"); // .zip extension automatically added

```

# Know Problems
## Malformed Structure
The PKZip structure is not completely build correctly, the native Window's ZIP utility will refuse to open the file.\
For the time being, use the 7-ZIP utility to handle the file.

## ServiceNow UTF-8 Encoding
The main problem of the class resides in the ServiceNow's `GlideSysAttachment.write()` method that translate the Unicode bytes into UTF-8 ones.

That means that certains bytes will be translated from a single bytes into two bytes (i.e. `F9` to `C3` `B9`), de-facto broking the PKZip structure.
This is impacting all bytes created direclty through code, be it the timestamp or the CRC-32 hash.

ServiceNow is aware of the bug but, at the moment, refuse to provide a solution.

For more information, refer to: [Any get GlideSysAttachment.write to work for binary files while in a scope?](https://www.servicenow.com/community/developer-forum/any-get-glidesysattachment-write-to-work-for-binary-files-while/m-p/1601628/page/3)

# Platform Configuration
Configuration of the development instance:\
**Scope**: Global\
**Build name**: Washingtondc\
**Build date**: 09-27-2024_0148\
**Build tag**: glide-washingtondc-12-20-2023__patch8-09-19-2024\
