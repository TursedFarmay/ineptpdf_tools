## DRM removal helper for 2023 FileOpen PDFs
This repository provides some tooling around the "updated" FileOpen DRM mechanism.

### How fileopen works
A fileopen PDF has a special encryption filter `FOPN_foweb` specified in the encryption object.
The encryption object contains additional information like the API server, a document ID, a user ID and lots of more settings and flags.
When the document is opened using a PDF reader with the fileopen plugin, the plugin uses the information in the encryption object to
do an API request to acquire the password needed to open the file.

The widely known tool ineptpdf stopped working when fileopen implemented a new API communication scheme using encrypted messages.
Basically they kept their protocol similar but encrypted the API request and response using a set of static RC4 keys:

The key selector, `nasca`, indexes a fixed code table to use 12 bytes as the key which is hashed with MD5.
The MD5 hash of this key is then used as the RC4 key.
The actual request and response data is base64 encoded (as well as urlencoded which does seem like a no-op for base64 data) in the field `nascd`.

Deploying "new" algorithms with MD5 and RC4 seems to be "enterprise-grade document security" in 2023 (quotation from fileopen website).

### PDF encryption algorithm
In the studied cases, the fileopen algorithm basically uses the old, standard RC4/MD5 algorithm that PDFs support since ages.
They just made it simpler and less secure.

While classic pdf encryption derives a (in old times) long "master key" from the user supplied password which is then used together with the object id to create per-object
encryption key, fileopen uses only a short "master key" consisting of 5 characters in the range of 0..9 and A..Z with the exact same algorithm (e.g. per-object encryption key).

We can brute force the master key directly, as the algorithm and the other parts of the key (e.g. the object id) is known.
We use a reasonably short zlib compressed stream object in the PDF because the inflate decompressor can verify the decompressed data to indicate a correct decryption.

Brute forcing the master key takes less than one minute on average on a normal computer:
First, we look for a reasonably short stream object in the PDF that has the FlateDecode filter set.
Then, we iterate through the key space from "00000" to "ZZZZZ", decrypting and decompressing the stream object's data with the known algorithm.
The acquired master key can then be used to decrypt the whole PDF for example by using a modified version of ineptpdf.

I was too lazy to fix the API server communication in ineptpdf so I went for the bruteforce path after I noticed the short master key size.
In the future, fixing the API might be reasonable, latest when they start implementing crypto from this century...

### Tools 

#### bruteforce

finds the fileopen code or pdf "master key"

```
make
./bruteforce in.pdf
# optional speedup, if you know your PDF contains a short compressed stream object later:
./bruteforce in.pdf 100
```

#### inspect_pdf

```
pip install pycrypto
python inspect_pdf.py -h
# display encryption info block:
python inspect_pdf.py in.pdf -i
# decode/inspect a specific object:
python inspect_pdf.py in.pdf -p master_key -d 27
```

#### decrypt_api_response

```
pip install pycrypto
python decrypt_api_response.py -h
python decrypt_api_response.py 64243 bZdefefDqEv
```

#### modified pdfminer.six

There is a subset of the pdfminer.six (20221105) in here.
By default, pdfminer (as well as other PDF tools) stop processing a file as soon as they notice they don't support the encryption algorithm.
The only way to stop pdfminer from doing this was commenting out the encryption setup in PDFDocument.
In this state, it provides us with nice tooling to work with the PDF files.

#### ineptpdf

`python2.7 ineptpdf.py master_key in.pdf out.pdf`

The actual decryption of the PDF is done by ineptpdf. The updated version in this repository supports being supplied with the fileopen decryption code.
Unfortunately, I was too lazy to convert it to python3 after I only got corrupt PDFs with simple tries.

Actually, the python 3 compatible ineptpdf for example available with DeDRM should be easily patchable as there is no specific support for fileopen neccessary.
Just set the key/cipher methods as following, supplying the fileopen decryption code as password:

```
        self.decrypt_key = password
        self.genkey = self.genkey_v2
        self.decipher = self.decrypt_rc4
```

#### batch processing

to backup a bunch of PDFs, the following snippets might come in handy:

```
touch keys
for I in *.pdf; do ./bruteforce "$I" 100 | tee -a keys; done
mkdir pdf
cat keys | sed -n "s/^UNZIP (\(.*\)).* \(.*\)/python2.7 ineptpdf.py \2 \"\1\" \"pdf\/\1\"/p" > decrypt.sh
chmod +x decrypt.sh
./decrypt.sh
```
