# havenwallet backend - a fork of a fully open sourced implementation of MyMonero backend

## Example compilation on Ubuntu 18.04

Below are example and basic instructions on how to setup up and run Open Monero on Ubuntu 16.04.
For other Linux operating systems, the instructions are analogical.

## compilation

- build haven with USE_SINGLE_BUILDDIR=1 make
- sudo apt install libmysql++-dev
- git clone --recursive https://github.com/haven-protocol-org/havenwallet-backend.git
- cd  havenwallet-backend
- mkdir build && cd build
- cmake -DMONERO_DIR=/path/to/haven .. ( don't forget the dots at the end )
- make


## hosting

The backend consists of three components that need to be setup for it to work:

 - MySql/Mariadb database - it stores user address (viewkey is not stored!),
 associated transactions, outputs, inputs and transaction import payments information.
 - Haven daemon - daemon must be running and fully sync, as this is
 where all transaction data is fetched from and used. Daemon also commits txs
 from the haven backend into the Haven network.
 - Backend - fully written in C++. It uses [restbed](https://github.com/Corvusoft/restbed/) to serve JSON REST to the frontend
 and [mysql++](http://www.tangentsoft.net/mysql++/) to interface the database. It also accesses Haven blockchain and "talks"
 with Haven deamon.



#### MariaDB/MySQL (using docker - not recommend for production)

The easiest way to setup MariaDB is through [docker](https://hub.docker.com/_/mariadb/) (assuming that you have docker setup and running)

Create mariadb container called `ommariadb` and root password of `root` (change these  how you want).

```
docker run --name ommariadb -p 3306:3306 -e MYSQL_ROOT_PASSWORD=root -d mariadb
```

Create openmonero database called `openmonero`.

```
cd openmonero/sql
docker exec -i ommariadb mysql -uroot -proot < openmonero.sql
```

#### PhpMyAdmin (using docker)
A good way to manage/view the openmonero database is through the
[PhpMyAdmin in docker](https://hub.docker.com/r/phpmyadmin/phpmyadmin/). Using docker,
this can be done:

```
docker run --name myadmin -d --link ommariadb:db -p 8080:80 phpmyadmin/phpmyadmin
```

where `ommariadb` is the name of docker container with mariadb, set in previous step.

With this, phpmyadmin should be avaliable at http://127.0.0.1:8080.


#### Nginx (using docker)

The fastest way to start up and server the frontend is through
[nginx docker image](https://hub.docker.com/_/nginx/).

```
docker run --name omhtml -p 80:80 -v /home/mwo/openmonero/html:/usr/share/nginx/html:ro -d nginx
```

where `omhtml` is docker container name, `80:80` will expose the frontend
on port 80 of the localhost, and `/home/mwo/openmonero/html` is the location on your host computer where the
frontend files are stored. All these can be changed to suit your requirements.

Go to localhost (http://127.0.0.1) and check if frontend is working.


#### Run Backend

Command line options

```bash
./openmonero -h
openmonero, Open Monero backend service:
  -h [ --help ] [=arg(=1)] (=0)         produce help message
  -t [ --testnet ] [=arg(=1)] (=0)      use testnet blockchain
  -s [ --stagenet ] [=arg(=1)] (=0)     use stagenet blockchain
  --do-not-relay [=arg(=1)] (=0)        does not relay txs to other nodes. 
                                        useful when testing construction and 
                                        submiting txs
  -p [ --port ] arg (=1984)             default port for restbed service of 
                                        Open Monero
  -c [ --config-file ] arg (=./config/config.json)
                                        Config file path.
  -m [ --monero-log-level ] arg (=1)    Monero log level 1-4, default is 1.
  -l [ --log-file ] arg (=./openmonero.log)
                                        Name and path to log file. -l "" to 
                                        disable log file.
```

Other backend options are in `confing/config.json`.

Before running `openmonero`:

 - edit `config/config.js` file with your settings. Especially set `frontend-url` and `database`
 connection details.
 - make sure haven daemon is running and fully sync. If using testnet or stagenet networks, use haven daemon
 with `--testnet` or `--stagenet` flags!


To start for mainnet:
```bash
./openmonero
```

To start for testnet:
```bash
./openmonero -t
```

To start for stagenet:
```bash
./openmonero -s
```

To start for stagenet with non-default location of `config.json` file:

```bash
./openmonero -s -c /path/to/config.json
```


## Haven wallet backend JSON REST API


#### get_version

Get version of the backend, its API and haven.

```bash
curl  -w "\n" -X POST http://127.0.0.1:1984/get_version
```
Example output:

```json
{
  "api": 65536,
  "blockchain_height": 965507,
  "git_branch_name": "upgrade_angularjs",
  "last_git_commit_date": "2017-07-25",
  "last_git_commit_hash": "456f9d6",
  "monero_version_full": "0.10.3.1-125f823"
}
```


`api` number is represented as `uint32_t`. In this case, `65536` represents
major version 1 and minor version 0.
In JavaScript, to get these numbers, one can do as follows:

```javascript
var api_major = response.data.api >> 16;
var api_minor = response.data.api & 0xffff;
```


### get_pricing_record

Get the offshore pricing record from the Haven daemon used to create an offshore tx in the frontend. `blockchain_height` input is optional.

```bash
curl  -w "\n" -X POST http://127.0.0.1:1984/get_pricing_record -d '{"blockchain_height": 965507}'
```

Output:

```json
{
  "blockchain_height": 965507,
  "pricing_record": {
    "sig_hex": "29b2cc1db4236a4503ccfb93b2ec8090be4f29f233d548b88d8acc13b8f35e158f8ec1fde53c964bb4e24b55f1e6e07904f08f8ffb13130d66a004f0af2db430",
    "unused1": 15945200000000,
    "unused2": 16066700000000,
    "unused3": 15488900000000,
    "xAG": 39949660000,
    "xAU": 577690000,
    "xAUD": 0,
    "xBTC": 0,
    "xCAD": 0,
    "xCHF": 0,
    "xCNY": 6541505850000,
    "xEUR": 848350550000,
    "xGBP": 0,
    "xJPY": 0,
    "xNOK": 0,
    "xNZD": 0,
    "xUSD": 15537885410000
  }
}
```

### login

Login an existing or a new user into OpenMonero.

```bash
curl  -w "\n" -X POST http://127.0.0.1:1984/login -d '{"address": "A2VTvE8bC9APsWFn3mQzgW8Xfcy2SP2CRUArD6ZtthNaWDuuvyhtBcZ8WDuYMRt1HhcnNQvpXVUavEiZ9waTbyBhP6RM8TV", "view_key": "041a241325326f9d86519b714a9b7f78b29111551757eeb6334d39c21f8b7400", "create_account": true, "generated_locally": true}'
```

Example output:
```json
{"generated_locally":false,"new_address":true,"start_height":0,"status":"success"}
```

### ping 

Pings a search thread for a given account to extend its life.

```bash
curl  -w "\n" -X POST http://127.0.0.1:1984/ping -d '{"address": "A2VTvE8bC9APsWFn3mQzgW8Xfcy2SP2CRUArD6ZtthNaWDuuvyhtBcZ8WDuYMRt1HhcnNQvpXVUavEiZ9waTbyBhP6RM8TV", "view_key": "041a241325326f9d86519b714a9b7f78b29111551757eeb6334d39c21f8b7400"}'
```

Example output:
```json
{"generated_locally":false,"new_address":true,"start_height":0,"status":"success"}
```

#### get_address_txs

Get the list of all txs for the given user with their possible spendings.

```bash
curl  -w "\n" -X POST http://127.0.0.1:1984/get_address_txs -d '{"address": "A2VTvE8bC9APsWFn3mQzgW8Xfcy2SP2CRUArD6ZtthNaWDuuvyhtBcZ8WDuYMRt1HhcnNQvpXVUavEiZ9waTbyBhP6RM8TV", "view_key": "041a241325326f9d86519b714a9b7f78b29111551757eeb6334d39c21f8b7400"}'
```

Output (only part shown):

```json
{
  "blockchain_height": 965512,
  "new_address": false,
  "scanned_block_height": 961405,
  "scanned_block_timestamp": 1500969813,
  "scanned_height": 0,
  "start_height": 957190,
  "status": "success",
  "total_xau_received": 683584012406,
  "total_xau_received_unlocked": 683584012406,
  "total_xhv_received": 43388479628538,
  "total_xhv_received_unlocked": 43388479628538,
  "total_xusd_received": 3683584012406,
  "total_xusd_received_unlocked": 3683584012406,
  // "total_" + xAsset + "_received": <Integer>,
  // "total_" + xAsset + "_received_unlocked": <Integer>,
  "transactions": [
    {
      "coinbase": false,
      "from_asset_type": "XHV",
      "hash": "2877c449a7a9f0a507c7a6e4ae17b43d96dc44369092e57adc4e6d9ddcde1a68",
      "height": 812669,
      "id": 831631,
      "mempool": false,
      "mixin": 4,
      "payment_id": "",
      "spent_outputs": [
        {
          "amount": 13659082425875,
          "asset_type": "XHV",
          "key_image": "0b6a04e1a1d7f149a8e8aeb91047b8ab4722de50554b88af4ed7646fd1929947",
          "mixin": 0,
          "out_index": 0,
          "tx_pub_key": ""
        }
      ],
      "timestamp": 1482567670,
      "to_asset_type": "XHV",
      "total_xhv_received": 0,
      "total_xhv_sent": 13659082425875,
      "tx_pub_key": "41bd5cb51aa26fb58d41acd25711a7ecc2d19be0c24b296a9e362aebee61d4d0",
      "unlock_time": 0
    },
    {
      "coinbase": true,
      "from_asset_type": "XHV",
      "hash": "1f76938b4deceb9e0722f02f4477006d3e96e2331552f726c47f297977434b9c",
      "height": 818908,
      "id": 838719,
      "mempool": false,
      "mixin": 0,
      "payment_id": "",
      "timestamp": 1483311688,
      "to_asset_type": "XHV",
      "total_xhv_received": 13388479628538,
      "total_xhv_sent": 0,
      "tx_pub_key": "3c71217add3b7882e8370fe6b903bc48059a79580af5e095485afc88b3126d09",
      "unlock_time": 818968
    },
    {
      "coinbase": false,
      "from_asset_type": "XHV",
      "hash": "53cb70ded276fbfcc68c98a8d9577b42c543bf1094d6cbb151fa05c9edb457be",
      "height": 818921,
      "id": 838735,
      "mempool": false,
      "mixin": 5,
      "payment_id": "",
      "spent_outputs": [
        {
          "amount": 12648774828503,
          "asset_type": "XHV",
          "key_image": "437518836c315bf989c5cc28b935280345ed672d727122f6d6c5c5ff32e98224",
          "mixin": 0,
          "out_index": 0,
          "tx_pub_key": ""
        }
      ],
      "timestamp": 1483313063,
      "to_asset_type": "XUSD",
      "total_xhv_sent": 12648774828503,
      "total_xusd_received": 3683584012406,
      "tx_pub_key": "3eac7a5ce7dc0cc78172522cef4591a43b0e9aab643ac3b57554fd0dbc8ba86a",
      "unlock_time": 0
    },
    {
      "coinbase": false,
      "from_asset_type": "XUSD",
      "hash": "a3cb70ded276fbfcc68c98a8d9577b42c543bf1094d6cbb151fa05c9edb457be",
      "height": 848921,
      "id": 848735,
      "mempool": false,
      "mixin": 5,
      "payment_id": "",
      "spent_outputs": [
        {
          "amount": 683584012406,
          "asset_type": "XUSD",
          "key_image": "937518836c315bf989c5cc28b935280345ed672d727122f6d6c5c5ff32e98224",
          "mixin": 0,
          "out_index": 0,
          "tx_pub_key": ""
        }
      ],
      "timestamp": 1483313063,
      "to_asset_type": "XAU",
      "total_xau_received": 83584012406,
      "total_xusd_sent": 683584012406,
      "tx_pub_key": "1eac7a5ce7dc0cc78172522cef4591a43b0e9aab643ac3b57554fd0dbc8ba86a",
      "unlock_time": 0
    }
  ]
}
```

#### get_address_info

Get the list of all possible spendings. Used when calcualted the wallet balance.

```bash
curl  -w "\n" -X POST http://127.0.0.1:1984/get_address_info -d '{"address": "A2VTvE8bC9APsWFn3mQzgW8Xfcy2SP2CRUArD6ZtthNaWDuuvyhtBcZ8WDuYMRt1HhcnNQvpXVUavEiZ9waTbyBhP6RM8TV", "view_key": "041a241325326f9d86519b714a9b7f78b29111551757eeb6334d39c21f8b7400"}'
```

Output (only part shown):

```json
{
  "blockchain_height": 965513,
  "locked_funds": 0,
  "new_address": false,
  "scanned_block_height": 965513,
  "scanned_block_timestamp": 1501466493,
  "scanned_height": 0,
  "spent_outputs": [
    {
      "amount": 13683584012406,
      "asset_type": "XHV",
      "key_image": "437518836c315bf989c5cc28b935280345ed672d727122f6d6c5c5ff32e98224",
      "mixin": 0,
      "out_index": 0,
      "tx_pub_key": ""
    },
    {
      "amount": 13683584012406,
      "asset_type": "XHV",
      "key_image": "ac3088ce17cc608bcf86db65e9061fe4b9b02573b997944e4ebf7d8e64e4a3b4",
      "mixin": 0,
      "out_index": 0,
      "tx_pub_key": ""
    },
    {
      "amount": 683584012406,
      "asset_type": "XUSD",
      "key_image": "937518836c315bf989c5cc28b935280345ed672d727122f6d6c5c5ff32e98224",
      "mixin": 0,
      "out_index": 0,
      "tx_pub_key": ""
    }
  ],
  "start_height": 855633,
  "total_xau_received": 683584012406,
  "total_xau_sent": 0,
  "total_xhv_received": 43388479628538,
  "total_xhv_sent": 26307857254378,
  "total_xusd_received": 3683584012406,
  "total_xusd_sent": 683584012406,
  // "total_" + xAsset + "_received": <Integer>,
  // "total_" + xAsset + "_sent": <Integer>
}
```


#### get_tx

Get details of a single tx.

```bash
curl  -w "\n" -X POST http://127.0.0.1:1984/get_tx -d '{"tx_hash": "bfbfbb3bfa169731a092891795be1c3c923a018882ac0efc0ed3e79e2d2b2e54"}'
```

Output (only part shown):

```json
{
  "coinbase": false,
  "error": "",
  "fee": 22893920000,
  "mixin_no": 11,
  "no_confirmations": 2898,
  "pub_key": "b753c863c64565ae81630bfdbf497f06955b6ce041f656565809d04be6ef9343",
  "size": 13461,
  "status": "OK",
  "tx_hash": "bfbfbb3bfa169731a092891795be1c3c923a018882ac0efc0ed3e79e2d2b2e54",
  "tx_height": 960491,
  "inputs": 0,
  "outputs": 0
}
```

#### get_unspent_outs

Get the list of all outputs with key images which could mean that the outouts
had already been spent. Thus they can't be used again. It is a job of the frontend
to filter out spent outputs based on the key images provided. Asset type defaults
to XHV.

```bash
curl  -w "\n" -X POST http://127.0.0.1:1984/get_unspent_outs -d '{"address": "A2VTvE8bC9APsWFn3mQzgW8Xfcy2SP2CRUArD6ZtthNaWDuuvyhtBcZ8WDuYMRt1HhcnNQvpXVUavEiZ9waTbyBhP6RM8TV", "view_key": "041a241325326f9d86519b714a9b7f78b29111551757eeb6334d39c21f8b7400", "asset_type": "XHV","amount":"0","mixin":4,"use_dust":false,"dust_threshold":"1000000000"}'
```

Output (only part shown):

```json
{
  "amount": 2746682935584926,
  "outputs": [
    {
      "amount": 2450000000000,
      "global_index": 86136,
      "height": 839599,
      "index": 0,
      "public_key": "6f6a4023bfa407ca1ce37f7382d5ea7540a330575bd570094b5add5e8ded2dd9",
      "rct": "4aca9e9b9a5d63fcf409ac28191696cabb78c0ba14791152509ebe6db7f9311033a1dc75d69a1dad7523f65856d07487aad2bee2098f5566b6d92ec5a5c68f00653d241a9d7f16ff13df87825609e8b2353ec20e50d11f8133d234184d9f8b03",
      "spend_key_images": [
        "2818dae0940fb945185c562fcb0a496f3c3b551f33b7ddd7ec1b5ecd856166e6"
      ],
      "timestamp": "2017-02-01 05:53:28",
      "tx_hash": "9d17084091beedc55c8a0cd342e441b7c0d89eeca25ac151b4b91fe1e12051e7",
      "tx_id": 2117,
      "tx_prefix_hash": "849f11f6b012c1557f87692ca7a67bcb24a5a553078c4faed870b8982821feee",
      "tx_pub_key": "4219b1004fa64bde0213bf3c59b9e160af8603be03d79e13148c15fd598e3a0e"
    },
    {
      "amount": 10000000000,
      "global_index": 86550,
      "height": 840011,
      "index": 0,
      "public_key": "5506e8786b7634a77487f0938a00d3de6ab005e2f76ffee05fee68d5165382f1",
      "rct": "6f78720d6bb0287d78c50bfa41332232fbc4bc9b7f04e35681ff926cc156b1fbfb3b84a2dcdc8cb98b33be70b302e380944abc3e7a7cbf3e27614936eccca40203447622e149ba1e09a7062eb8910acf029f561ecdaa5a34e076baff5d63770e",
      "spend_key_images": [
        "9c82226bdf165fd2424d9a0ead661682bfab2fe644cd0bcef575ae16595c550c"
      ],
      "timestamp": "2017-02-02 03:18:18",
      "tx_hash": "8257367ca6def69dc3d280e8909c3cd01b230fc9922c9a89217db06f3fb41102",
      "tx_id": 2118,
      "tx_prefix_hash": "781a0ce699865987ec78ad331e8e89c0d14461f9881dd11a7a4541114b567568",
      "tx_pub_key": "29ceefd594b856c7c06d2423be17cd674b97d1d8f72907ace8d27f5b6aa9875c"
    }
  ],
  "per_kb_fee": 2480631964
}
```

#### get_random_outs

Get random outputs from the monero daemon to be used as ring members
when making a tx in the frontend.

```bash
curl  -w "\n" -X POST http://127.0.0.1:1984/get_random_outs -d '{"amounts":["0","0"],"count":5}'
```

Output (only part shown):

```json
  "amount_outs": [
    {
      "amount": 0,
      "outputs": [
        {
          "global_index": 48449,
          "public_key": "637dbadf193fa9fd5c50c96af18f458a9b7d4844fdf7ffdfa3f62d51d6aff835",
          "rct": "0c908e1969edfe7824560104e44334b46ced17c9462eacb5aaa70e62ea34a394837c07d14bffc5a65e2dd14da395dd135bcc2e5ac70648782d76e4a9920cd007b9ffe319b796c555fb7713a270f21181a5ee5c8b01259becba0dd332b93a6c02"
        },
        {
          "global_index": 67558,
          "public_key": "6ca3a73512dadd669430f73809c949f3edf71728bea5201441c648c2d128c453",
          "rct": "999312ca1914895cf8a517c91a54a069d8fdc7205d7768173618e77fad2fde5c725604d666b101c9ae19c72e07cf5f821603a7b63efb5dfd8a7c0e36ed0c250fa92929cda49ddd0d34e664e15634ee59e958815764ec979b5ff0a72b3af6af0a"
        },
        {
          "global_index": 102186,
          "public_key": "c29d43f5d7c71a6f1b4f3286da3c296a083cf68728d85c268ee0c964a6c8c00e",
          "rct": "23aa82efdbd0c6878060496a13f7a707a6f45649b51de12d54d0cad14c5be5bd00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        },
        {
          "global_index": 96992,
          "public_key": "fb83d74a42abe65d5b8a6a906791202376b91e3459a31737ac62a401b7b9356c",
          "rct": "975b42f50cabb801091c90a4227bf7ba024ddacfeda7e5e0383f034b0bc8ba2500000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        },
        {
          "global_index": 36848,
          "public_key": "2a8785e42a9446785cf189a40fca8f56a592dab9db1f38f8e8a3d2eb84b680ff",
          "rct": "a09e27b83917792bc8f6c51b40077aea329bf08b569e63657e2ac3529db5d0aa14f9f9fc45930577b43829119847ac857d69c00d12859a903cfcbf470819dc00b1bfa43aa979e46a0d0476cb36717e8d8374afe9af1fb3715091147cc9587e0e"
        }
      ]
    }
  ]
}
```


#### submit_raw_tx

Submit raw tx in hex generated by the fronted to be relayed to monero network.

```bash
curl  -w "\n" -X POST http://127.0.0.1:1984/submit_raw_tx -d '{"tx":"020001020007bdcc019e8401806af20f8d0dd72cab40d8b798c19cbff78ac28bf6b7a2141e8ddd2af09a669440c4983e2c7bacbd4f240200027d6a157b6d00e3175c604cdd7f9b0d537b1ba4b1c949d60ce68c644a6ab037d50002251f9554df370da5e50900e38f207a43bc0e131f560238a42bf20166b48300f62101a00552a9b0f7b18526965cf510a1531d65439ada0c3c7f32d3f4959cace001f50180d1c2a0e501123ca835307de9442233acb55d346bf36a1d150e34525a8cc7bed0a6a08ccd09f76aadc775cb0dc836a802e81fc5dd1f3d4157f1553a50e7e4e0987b21963900d8607d200a3753897e958caf0b4b3ff281995fc1c37f8334492db83b6cd2c40d16dd2266d741e67d9a672d27a00cac3e028addc19f2e21d37ee9e44c68291300d58fd455e3bf47404453605b410848a8cee68bfe1124dc55126e1dbc4acce3adaca5c9b7a041c708ba1eb6b97d762c28cd8b1619cc6128f0d8ccb91765f3ec93db17778c5f480d5ca3142b91627e3c9016580a7f44ec07ff850dbb4960f63d02696b2a632c54ec7f4493b2f9ea49dae525a2b4335cd8c7770753b10bb740ab0f281040530588a7a6f14b5bb6d763d1434dd4e065142fba2172bcc92cdd1d410487fc9394cfe740452fadd9ce3cb0d7bd5dbd5443ec80d37fae0598d44d270c065ae041f4d3bc657ef3ca2e1b9ef072bfd8ea79e283ef8e2c151c6ba0a0dfbf08b332b8df37d7db48fbdce1bc50ab6d47301f62bdc5c5f7f9bbc8cf9ac4d254075b44d008d30a9539ee288c73d126ab6545c6e5f7d902ce61533445f184bb840db8ef0ebe6a34ad48ae5d60a0d1d542658d5fce93b28bbe2d9c7c330f0b82cf009d5dcbcf19b88a91c7cf82af78591fbde26a2ba9732674393a3e55faac33320d9e67c14f96d75faf24b7fa8e9eb9bfcf69a7157c0578c1b61df912b2aafdbb0a1d75551ae84ac72bad62bb6b8ab9ab1b4528dff0a8d8f30f791c07a8339d1a0993944136122f0afae3dba4b77d75d93d4116258cf2875251522ad3f57d2f01074433ef9a06738e9571c77dba72921a8dc8a313d2a88473d9f117e19535db8a094126cce97c097d0fc344f110ba3b6f31f7f11f8aa3790ac9de80abe9166caa021ef71cd41752d4da91fea2a5b9bb80e1ca11b651dcd5d870da16e383705c510c2beec911c63c2bd60221145d5523d141cdd7f1144b63d8be16b6290f49beaa06d0250071ff9885c2f8ea02a201ec7f42e51fde3bf1ee3dc87caeecf6f8efc70ebf30d7f3914ef26659dcd6d274c1aab82765b76cbefad53b6cfb02622416d9000b55ad09d0d99a00f68136260fe1f1415054d8b7fdab61bd324167d1d327ef08081e2c1e535a8446bff64c618ffc1b343e4f6567efa11ff9f864c550e553c60eb390f2ac408209c1c0e50de3bda3f003dab4b5c50c313058bcdc1eb65d949501762c3675fa5d9bb1e901f3dd82f42dab0ae841f348babe25770b8ecd49edeb095e57f341b898e646ec4486f715d0fbce212aacbef82b0366dbb0b4bf88dc36047b79b3e3bcaaf5e3efb6c5dbbfc3bb0f18be231550a4d0026e095e7db835570a62fb425ac1c933471a60508541b25b7556a3333a9ca6ec4a5d3ecedb00a7c8041612003d2523bf61a02aa633874aced4bae10fcc52fe0ffbde5b2acb21a6590fa1f75bda400d26715a81dcfe2fb150d1e6de07c076e4e5c22e377950405f020a902242dde89c22d7fdfd1fbe0ce4d216d131a1e8af40fc6f4516bbae44102a0bf73d04baecc35bfc83604a86eaff58d8233c9af9a7c31a28842ae7ccfd3036050ec770fad79e0be63e2d2f1a8d7c4f2d62b1ebe1d8ce3cc8514042eebcba320248752e30005f172fed893c9748038506367dcaeaf06c31755ac916864e0fe1048825f236604b116d583651b6779012d165041b36504fb937cecc788f721f860ea53ab41168ac80b6dff2b8007a95e6c8e131c77405c8dd6670b11d32b2a6d00d72d753459a4b636e04da4d9e0fcfc501aa1097c4a7495d6f6ab60cd0c9d3900c6bb1c06e0fa5129f8784631943764a3452f77211d52dec5036bebb5450f1430374f35a1b6399ba72df166bf67e9e4dd198dfa48527fec2f5c6c738e37e24c3044aef06e2bd80e9ede8afb12d8cd2d674c6b9b4c1131b5acc45431b009e468504d9a7b066f008c82dc3081cc7ea333593970d32e893e28de127363ac4f722c00715b9390b7cd7fc0a28a622011428839e49948ac387793135f1b73b9eb7b84e0a82104a47ef231ad4bc164dd40060493d7b1d866a975a3dd98c07678e34a7120edbb305097c1148b2a9baadc7f3874a05c72b97a363cfad232c885eeb6d00be0036df0f06019244264efc4fd63efe0ecf7a3607f6cb07c3c5d0fbbce459c86b0a2202c25cdb9fc211ad458174ee75a392b1cf08193c5534a3644732ad4bfe46035b9126d95db6254cbdc3e78d873ca7ca1e4416761bde4bd8a91be1320a8cf00d6829938d196dfd3a85598faf2f4981884422a387dbfdaf6783b8b89a7318140ed2b8b339b26e7a8ddf0a78b12055db5bc8c2a2465480c3eafd4d01c2f8e754088cd37da11dddf103a58ee2c96994499dd67139a478aa5ffeb39277797761710ffecf3efad111588b9a9dbbf46bc64e504361cc042b98394bbbba394296e75505949ea033ea3358d7fb343eacefdb0557d8058762110b94e8a792ce55adb6ed0b49528b1f2fe5d6f3be2ece6a355dd741d1bf41c80867a0e6738d96b6c127510c6b2790f4a444896c9f176e52b70de4c5a1ee4e6a3e5558a96786957827ff2700a3ef377178ace3d4678ba4f43987bccbdc4dcc07ba93ba0a5fdf43629ed5a70aff5e4bc17ac814e5c33e8a394a36333ab95f3551b62d17a68514dc6d27cdce034d78641e034746222a3ef07682881fb0244eeb91858493c29185fbecd2353f06ade9a99f69a79cdc8cef819436952800d6cc921eb04a9db6e78b1255eeba4e0222e038c7cbed178e549e2b9781f4b1b05d324ecffde6213bc61c3c17dfef8e08313fc8f2a877b68d1a1108f1e99727178ce1b85eccf6f487c9cc4f4531b3e3010523c8aaa61e8917f2afe2731c214742c77124a77b56e99dc071cde39e3f8a07a74b417c65ddb1cc995da7dcacc36262faf68cf846cf80f6ad0980650643c305e5875b36005f0604cf5491b2aee281db708f0516f56fe2089f3fd4c0b1b1ac04579bab149351185b8ca1bdc83f4dfbf1502516592de3612c6d66c825d0405102ae6163cfb64d173cd7fa661ea5f67302eb2e367e4fba402f2d2c835b6ed2380a6a1e7fc6ee876418a74d36494cb849354d246ab98edd90bfa25d06db67463e0f02c1c4a9ff4025e2de4bc9920d4f03f72fff14f4f9d495a6dfdfac7a2b5bf10b4b7a7e0b79175659d081c15390821fda49d1867e0bb1ed5d33d46a843958650103ce9e348eabe90a8e14496d982df58a8f86a16d0e35335614a81068af32be0c7681f6e01918d054c7504f3a0febd0a96ea958f9c604ba45a0b4d0480ca51f0692ca08a55772b7e43039bfe54ed41f8b565e0b74b35f00be8e8287e84411e5041fcbd6bbdaf3a472b9a2c02163649bc46032aaee580dba8a66cd488c12b62e086fc193897ff55b6777ffff75cdefeacb1be3637941ada1264cd7b9e55088c20fb7cf9f83553a2c03cf985786b564cd89217d69535d6d9ac6c305b43872ac0208d5ba9863fdadf5c1f47a0e76bbd6e2945591e2cdc41b1d9ad5c285a206e00205fad4a72194fd040193dd8bb70709c6c37126214d49b7375e4b76cfab3ca4e00f7f059eb6ab01f6c10144b085ce52c48abfb6de9b9c7e0cbbbfe148802af1090f342ee99a166ece18116eef2410c97914bf482e563b00146958c49feaa7b6740e2feec083e7f8afc88a9f2247ea44743abc8f016b598f22657851f46d92cf7a02fc3f9b31a49195697b196622333a3a25467b0b6e947843199ab257fb92d8570e8acac0c29b238907a6faacc6afd0dcbf92fdf3b5f63cb4e74bb7f0609f00e00b2c083c6375d788fb490fad270830b01ab6a3e23ece2e37ce9460d3ab36d8da0a0504fb87bcb311f0edf860a03e7033f20600d2a77203d808ef64ea07d5b033047d8d21751446f26f4890120486686949693849ecae493ba6c6f361243729770fc9fd87ca3471ff4352787acfbe51822c2ece02c4dea1fc752bdbbaed3749080ec41b593b36c7f55743452be56276fed4504e0c3723714eb67af8af6b4000160f5a628bd1e7bc4dfb31ef9744d6a10f250185132244b4776502a59153b210740f075631a56d45e72edbd7644446fd6ea66635925ee7f9e77aca0917bd569eaa0a70029e2a8ada8c94465ade6debf4290c3eb987e39fa63988d8a34c61bb1f2e0c01b9c673a464176c4f012e372f7fce51ec78074f7ac08cb455e81e6e77710e014d1285c5d3de89a9e59c0735055b310777c63d2d69f9524698b256ab7aa9a10c8886522d7e17a98faaa274c90c00ea83fb575ece80aa7002e4a340d229e43c069737335e67790785686d2cdbe95d24eeca499f2d6405277a972d9e571788c406629d172476d708d82cccecda373f84e72ae6c370a1d9606c4a79bf2ef95a7609b3c8b6d74a6989ee44137f791655d9bd286b5d6dcc18eaa6c3661703addfac03e1428e91bb031f54ba9d672fc3fc1008496ce7a0fff161dd356bccad1b864d06d26475368731408d52fe91b10cc79557718ca636fd5f1bbfa47471416c6dd308c870b1cce41ecd0bc6be60c029911971f83b40a2df1691d75413cdf6b475d00efb701551d462645366e46f07c1c87aa84e8826f12b66351a4d13ba73cae35c0632525a0dedb1db82bbee0ed295458b088bb217b7029c4788230cc00a429c9b00b073f3ec3307b1c6e86f491fc865e1df3159e2aefeccc5108c2b5315caffed0bd40ae571f84512b3473718f48459dc8f394210f18b35203038188e72acd51607246422196e958af8c1add8155587120ed7678eb3971d2d6c15dde3a063ffe80d4b400f77392c3012561e8dfd4ecb236611d5ecfb51beb98f8b9355cdffdcee0adcf64a91469ef2bb8537f37ee029c56b3ac33f7539f139cf57df1e2cada2950f7e066a5a5d4d852ca9e7ed0c5788031197cb14d5026572579804696259f0a40c8c179cded9274a8fe739d4741fb865907fe81ace963cd7f8486259bcb3390a0c8d1d85a2801bcb69bd51928274dc1c68e78d8d98d6a3e6a36cc510e1ab6f200e7d43ebdecd717502aa9c1b7fd49e3f7c8008fbea25867b7d34117b62d75a61051185f0793838ef3792f95e2b780c2f3231bd149ac218479331bbbb27994acd053f9a52a3ad961d450a7d393d0034424d1c4355814f40dc7950d6812b23416007ebb0f66ce3b26bdb165f06cc8aee50c6dc15ad2bc424e36291a63674052fba0dfbbd3c840df9d19cb34852d61dfb31f78e3336cc6ddadfd7414e43e3f56c820a0b594cf7e46bcba2c7f347ec8d7eb9b7ff01e4d7e854d36be871f9c90039570928b55c0b70d3d2865775db1b17ea0349d0dee1cf129d26ef2614d149aac09109b382c936ff05e3e3b4bb654d43213dbcacd8169268f4cf7a6caaf24e3fc23d077607d9d24eeb0984e5e786082f0e6ea8baf3a628d95bf6cad2f272d220c88202dbbdd627a41c0518117d791c1dade4a182dcb58625599089be70153bebf1ac03fb028d23d0bf5da5e263212824f0ab54df97d02c8dff205abfffc8388e6839076ea0cf5e82318b6b303fee4d2f0c693d26cde78697d7f873abccca3b17dd28079fdcad94a7626ad4247347adf09a7df8108734a42608a683c45342081a128d0e84287d2bb39ee38ff309a22b779e9e4212e0ce902e46c4027a3e54594a2722083029ee2d323859592d88a9a82c79ac02bffd1202292e439ab178cda257dc340c947ff311f8fd6521f06ec23d7adfb45afbf2de781222a90d7a093f8fe3d88a0b2b3c558f4c8d9044020468341dc6e5bd8c5127f14944d5e63eeb2ad621c28500cd22babde8135f24a233964854c6791d03b5d10baff06cf084bd8fdf7131e50ce90e8c03f0e1dbe59cb5a9f40671f5e50b549f71df51bff3412c4fdcc5b0ed0e7c13306434ae9a75e8c33bbbf70f2ca9147b74668e7f5fc92fb016ed880dda0387042e836a71e4cc242aeddd4b2e5ffc526977ff97c0417190bf21935e364104c6c405e231145425340e3f813aaecfd55eb0dc500f9d5763547e7c5cdc4f8d09aef7dea9874673ec1c7d66ffacb50171f2db96cb0ff3b1e4aa306127a7c1130d34516baedc1f08a9f8feac28d2869c18ec03b57ccdae921a3620708e4cb34a0c570d766e41373a08e15a998dea56e1f38168eb6bc575a72a9f4f09dece13e301ccbc34e09f0bbc5bb8b93c1496c45d7bf1f92b7e92bf0d33bb9a53e91917d7fa015e6dfce17c0ed88956dd2223501475378de03d3814dc51ceef4633b5be4de5d2039ea501fce9f1b15700dc769abdeaa2d761894f39149caeb2b1a1f9a4a5223ee2aa9b1e51f826368915621b4b389cc30f6a5be8150e865f0cf5eeebb5b76cc2bcc8d03262297d2f5f76ef81ed57b8c35fb7ac9cecdb4e6ce416a2b59056b6ee899c3dab7b0b1de217cc1fd2d621ee08204f776066fa3dddcb3619fece373660f888a631918532096fdf11d4fbf4481c0fb9a625a6508ec0d74089fbd9361ecc312f7739a3fa47589a0e45e4eedbe9bdaeb7bdf6f02c16af4e953f58d45f531fe06849ddbc7fb29095253271cc7e4f7e8d3f8fdf3826ad393704aacdb31b1c26e99301db5a4be4ae9a4e622d4cc90e8cdfa06ed8d4c63b8a7fe03159dfadbada037380c94929d52970c59ea4506fec41f4b02bca6388a15dca18368279ff305fa8422057e57159819ac46ad83b8ed0f036287ed46be9c55c66b62affef09b6bf131285d01bfc6b7ea1a889675c7c3554779b7589b49eee8b7471e79ddff860c10f1db5ab64ffb84cf987ca11735085530b1fb737f33119779c4811ed857f6e4c2fab69fcdc2ffb09c410eaf9353b63004ffddf6cf954eaa97efb55cc28c12e7195af37ff93cf75076af42aef805cc1b08872d634089dd22e8fc6aa735b11cab1c7d2970d6abcd9d2cb55c2668151967175882ee21440481c3693fed3e2b59307c5050ea5e408dfe921dd3bf49d11d0ca4c346b8d97d233671e3f67702fedb207b32a48bcb96860519dd9285680d9973e061cbaccdfe631f172064fcffeab97271eb6e39e8dfab3f84b814328c3bb118331118668e4bed87ab5b170091a59d0f9d0f7d47bd0d0209d785af826394287fee4ed427bdda582538c18f831a051032a04873901b7c729e89817e4b9be90b72dbc8105633de806e13b239592faefd7a1235d87c50932e351edcce8c70b694b98e0a0c154fcbe189d454648204a28ff84ea021a2143c8948e06ae0c9a3111d4697dab1c521e12198c1d299e32d3b5f9de6871816ab653d93cb97378178fc27d7b21b905131e7d804ee8186d698b474f41e7509cdd724a3b5b88d7af2637f6d4905184c12b6ecd97b584ecc6d6017eed9018d1bf48e08b0cb75e288a6e122b8f9b5a47f5e497c5389abc8e264c85b8d5883e387be88ce55ccf263212d59cd908979a6c61fe72f65cd059c1c30abbe1d23da5d8f56ec2a7be3a6e02638bff117e0e132d3c41046ef6b040715b7ded2764ad69c7bbf8d339cae8df63f25870f3968c08fd3c81d97a7b9da2b178f999ed11b6b78939ca407bb6212ade2b2bbc41b132f2572fcce3b4ed9fce3792749c79a09dff61bbd29335fd72b54b5049614c6ca4c767bcb7a9e7d48fdc5886602d99163b5668d1b3f57d71dc4e5b0c21b3b4dfea83a9d3591f54e5981525d02701db090d0f9e56149069731f01ecb4034d91bbd059d980d439d4507a1a47d574c90bdc0e4e4530d37e94f00aa11fc414690eb18cd8516960381fbaabb0f4bb278c8024280a3ca0f592860b9eb6a9bfe6dc65e43c220f1cdd76b4fcbc7f895dbaf125517d4a3efc93a062d6fa866c306d9130c9320072cfff46ff1ee7873cf15b558080ea8b447362ba2f2d61fd367870309e3cadc5202f93f9e4760dd10a7ef117d9508cc32b6e7a19ec8f5a2f8280d8400dee92a84d4d853abb95b2fa8f557775522d456e9f28c132db5c35ca0e536dbbe17191b63c79d5c43a41b23a2b6cb1d6bf9ad87195c5bcc0b2a375610809c5bec4949093040963426606be988b8101395251751518827a57527d90684eaa56a088717f1fd2a691319a1e6f4814d626071302d971fff30558104363f6a28fc6f3b8bc1239d32cfb8523cc42144e4c81bea7955a151cfd47cf9c0e05926bedaf266b93da7bb0c7adb512b67b168172702b7a6ba286065cc660637419ac47d669899d88cdf4f45d7fceaf7ec7fc996d60d4b41f208c197bfffb04e9f4a2d0ea5f215ba7aa20bb1aa6539cb615daa30c8ab0ba89625067e7040f68f1ff8f113dea1ce1043679284a70ed2a9f4308f0f6341d66f80577bc5df43176fecf126c226d884ccd1b511337b8cfa19c7c339f47147bbb9672b4941e2702e2f439623fadfd79e8ff81edd22706c4dd799b55f5ca6343b14e9b7590bdc7bf6ea6bb4e7c6d0358719188509c11013c3dca2d8d018141b04aa4ec768706c0f89c4d9aeade36a723cb44f42f5b51ef54aab3b503766b852985fe23636561e153c1ad55cba3f3218b4dc35be2be0b8ff3c8098f0846a2f9a59d7b80b2984f51913914aa6d2e0000b73ddb7e871f00197dbbdab1fddd8e697c2237eb48703746f0b13b68d5bdaf32984cff4fd12b02e562e62942249312317f12432343352a6f998482dda10b6b36caf7aa08a9be16d9dd05252bc49258bd07ba86f32f2799eaaff0ecccf027563fdd81dcb9770fa3e67929e53f48d7869a801a67b0d47c4eb885e9521c5d55361679344df5dc13e27f27e9841beca192a5d13e3f35b5d1d810f0612ffebc122e5331011786d752f2d5987cff285693c44f7face817b77b107ec6407c169a98dba9ed32d4993f21c33b3a20a9017b7926cf71068334373f1b5fb9928a0ed23a6fc10f72b3e2410909346da69cd667f8aa5de180c94bad1fc009b1cbc2f8fdf0b8ade07f192bc30932b9e88c0ebb1623f9719480de0ad26fba2daf412eb685c7ea7dc59d2c10f4e2c4b8f2b402cc5f24f23a9c5b04416431636415bda065fa0fa36c705c3ac23c11275078623e9c90b5909df108132e7de527a9e7c37f1dcef356add96f917be2f8e83eeef6a28d722bce6e219002d0389fff016e7bbadfb777ce056c403271ca083dc2f02f5cf84b9b8c8477960021d1a9cf69d6b37cde7eb55b83c0913a7be2292a87ff9cfa5270d30b5fda9f0f2c2c4671a30c40bcb5fb1c61dd9a7d3f7af4803d1549210ea4374a758337010687d0ad17d89c250878c5761eecfa41889501aab3e197af77cd40fed1dfa1da0b0d795a086f855363f3acf419e8b53a832fd408ecc9ed4dc6ac43d5148e028406ba5619237f003828746d8c858e3c6826db3e3692bfd4e74de6d80ee72dc9dd0aaf7c58205f76d137967d68df254a5154bc6a27917f931fd9a218f1aae68acb00d3d75bc8675f0a8db938d097adb0c8f3c87f8b6e86ad0ea8f50d8f42dfabf803ba8adf2315c89a2a9590257b55a20242994057c30d382a9d95632a79d2858a0336c14289a7368e1ebb877e50520699ade10ac83d55c0e5170601d5518e404106f5a85667d3f57e8cbf8adbf83c800fb10895b58be3e65cbe51da1062c505b90b325d5d29ad98f4b5e8ff5654805a08fd661d4337aa32da5ca604f7611909130bed31de0300a06b352d3154b26bbe5ed4ab5485f9f8be8b9e0412a14c26444b0931e45df217882a206816fe597f7cd0713366ad5aaaab251fd075d5c11d131104e7dc189557a8b9775db12611d1d4d242cb6609b469f65843c41cc40f2167a204264d0431c5cbc06cd903531fcbd06c12f8672848517592a341ddd86730952a00ab3c321c41cfc3039f0a50bb4566547bbb22ce299d41710172e126646103ea095cb2eb968f6db47729c2e28d0df55f3d1deabdb21fd1f4e6fda19bc9faee8506330ecc5fa9831c9c169b294b84765fce985b8f52a663b63b87e3ba15b2d9410c5adab395815563eae57ba15453708ca0dfd6948bc1c95386d1f79b4b7b33b20f5a210f3a6ec1e1652be07b0cf1b7afc2e39bb7c4ebd72da0346f6bb907a9bf0cd953e605cffa3cdd626585d672ed99cef6df9d3e1f8134b9492bd6288027e6016b75bb1b3c9de64464f76f6640bd23654459dd1f24c828f46cdd8528ba1ed20098e43739087d61f81d9d9a91c38f6d66818334cf180663ff9a8c9013f251f3074ca4528c2d66f3dd55eede72e69ba112714ef0543845b846a2e8d6a72e97fc02e1b8fcd7e00b52107851d110a5b639d516a6d6e032435866d8301592300e9f0da385ef70472f770374667060055b003a7a516cb6a6289b8f2bdef5da62befc041d2a97a4bdc7a72746728a832174a8c15e9cd5e38b17daaa5f81281a5cf6470a5679d461dec70470f31d951dd339f5825c2e26a73f7b24a648f1c2e96f36770826975acca2cf0bb8c5edcc192949fd29d02561c19580e8e274240b0d6ae1750264083f7ee10ba3d69c0f2c8594646b3ba7cac9ed2193affb434dac0971294d00554fb45e8221bb7f21c435fdab9705d09e3503dd56743863467bb422463ead0fa73e2639a8ae37781c5967ab3d9c6d92a16a704b35d633250b91756aa6fca60ec61441469c09c0a2a44566c7c6f257d68680bb7e992d9a2aa9ce0275ce2c41058989f665a15d09c5a3542e9c3317bb8d6d1b87f1502d71c09ab1a242dd15ad08306fc6a6f4178285b44e900466fd94466e9ee41148f6c2a51fdace980517c60da2d7f22a8215b1e467d69ef8d2f1529b6222b14a219b83d5a7302df9b22cf10b920d7e1ba516bb6ace0053ff2a6cd2c08ddad1d2576a8d0699f49fe3755b3008b93cfb61872dfe917ae43352769b2bb19438006909b11fc50324406388fc8105dec0212e0cf996090456da1bada9d2aed0d76cd12bf0779efc89eab95cbeef02e0537a6ede64ad90d677c1f1a524531fba325ce049d1bd91acfd01458ac0ae0054128aca5bd84e8fece89556db0166dd8d55e7f52660c2f1179d490847737703de3701f612092aead8d07d5d54813ce2ffc8296940a042646ba7b812c2f44204b48ef1c713930cb0fae4aa01354c09e2979ed61f439139ac40876c3b9259220e48c54d23e699f38bf82d7e58ecc4f36f684bbdd3f3151bfc8e3138384c16970e446b815a8d40cfb3ea8373758baef4d8040b76b689838b585dac300e205a590eeb795c255dd566cce6b886ec2836eadde71da600e69f7c4595c48993c594ec05334d5f2b45dfd75b064ea4c74961b07b0db9a8fd9b104ca6d1f7e866853b7d0d2ad462e6d884f78d9fbd76c7b9a7ea3717f98c24759e22fa755fbca1fa62f400cfdaf5afcc945b9e3c6a50b5532cd5ca89361bb3550f6ca27481aee23d65930a94729eadcc4b03ff57ba9e996e60d1bc4139e784dbbe3e885d7df4ceed2ab50f51340adf42372dbb7eb372b6d8a30e5266b0d22abb38fa6203082980a7791b0eeb3bc71cdfe21e2f1b4fa1010095d87a85c59e087bb5af9d401ce9614fec7503a4863ac0a15798624c81c0e705adbd315df4a44f46557b63ad4e2e0710178400ddcb10bb9f32a649601ead4216d8dc3674f56c48340f7fb38a794e9652e48a04929ada41520be2395c11939641222a51bf873d580590bca45b23bb3e09ca4100d9a90eb38c8c5344e41b42ca0ab22698e355fbdfb052dc5fad75d0b0ed5ddc0e028ab8a6176f24ec70ba64fdf3f5b0f8f93f6f5ebc77ce2d6fe023787736a90ca43757bce96fd6dfb496e8aa288ae809be06000f3504f229104584ebc8604e0804af9abc70c4030b001bca9d234fdb477a7665e4304f34d4250ac3dbdf193a02e25ed377f485900e625661f107d81225c22a13b0d646ff34f700ee249606c30679fbda4e7d55d571a00963ae3ad37cc9dd558bff76287911aab377463140db07f24bdc80052076c6e6129c4663f3ae246a94c703a1b113043debde5adbe026019d46b34f138208c48473a1ee866ec984000d1f4a53aaae879c2cc6a9b9cbaf0902302d4ace36e194806b9c580109a481fc00b50f889e3ce0e68a3842a8db250b8cded23ff229bcba71bd07df899a6026aca13a610652d4eefb36425d314e060c5fbd30a988b573c034cdbdba0bbaba2d7130c594d44d15346134d13aa0d4230e395c3a56ff8c9e47465cc4e54c840b66002fa266f1865d92abf7d178d89682084bfd42df6aefd3235a99eef91c337e8a62c97ee7d31ca2fff2822149d5ea49074fd542601a864d21ed48a0f6cd7dc98e6d99d234607f9ba8d684c9afc506a306e7e1a54d1f37b498e79e490467f0b6677edf9eaec9d5575fdd40e4443c6be80f69b8d1d17f3eee073c19dfedff5d37be7d844d90f9fc6d14cc4772dd1b70ab09c937e3724affbf417ebb91bd6f8b1b7c2cb23e7b0305242957624fdbf6fafd0d1bdc8968f8d13dd4b4c1ee2ef8c3d7723aa6a202067f9a320743221cce2bdf0de49c3836c56705a15b6c4508641c939d7be9e8644ba750be2a5269b9739bfe052c44985b2eb1ec090bc417b0f33bde27965ffec4bf47199c1bd94e4833c21d068eb6d0cc045c5a8201abe216a295c88606c6d4b51a66294f7b1467a7136f0804c991a00927cc588a5d3516f33567e28f8d9a3f9c9c6ba009bf3d57771401a4007e4046352b8998790bdfc4b9b6a6a1385ff1259342974de051c07e1b91337b0b642580bb7866fad9e35fc5287b9722d64f2ffe6db1abea9bb3b7005d9103eb00e01d64b9a5e2aa79aa918e4453092b568e1af859e9defc15fd5c65ee0a6291069e8d03755b993b11805179f1000b2d0080f65fc163681f79eaf7f4ea1c619b0b2a79da5cef0f9b8de940a3a4ceec644e42067911d157ad47c6a93b7659a088049d7e760f22482733641fa84e92c679043343d1b8c6155b70648967c8b7a5b80a3e6ebfe817d8844f67d230a8b775462d8bdff3a3d081790a620acf2f0db1a20fab29f8a382c9e8559f5074008e60c93210e43a30f9b60b45ce48c300b87ce7042b4690e4fcfe584d66493a8c9656428d9554472af794e074fee81b4c8243800bcc53ea8b6109414918a7db0dd1d1fb801f735e0702192c3dec5c51ce0f13dc0682a5eb80a2c10d953d79e77fde5bc0fd6252377009c50e76e3166179e2b6f4069b6853f365590008f29ed1cfdd0542394151cb9f6385837681176f94f9461d0055f08dc07c23339262c1bcaa1eb72c6e2c3f5bf8415505ef002306a87ae0f40ead3cffd6a4354a09350ab539797394c83b62d90b9224fa2efa93ad4f206f5a0b74270efe8ca681a25a6df0812a434b5b0fb51cd696241fb040c4ab1d298f0101efb515ec727a3d01d1a3417ed7a97949eed9e2e6001a8b2588ea4b165798ce01b44d190c5c0f973902c0de06034014f394bd2250045c62c1e68a2900181034039966df6d513e23b43d29f7a7599c9f31afec7a9ed9869fa50ef26d01101d470e0826d37ab0d1f9752525b9b6ae5c380ac49a6416be19b8bc0f773fe2dd6bce09cd774a4cd27f88be499f440b3c8f89b5a4f95b947df08c464f10034fddd2010fcc03d254e508a992c0d0e56d3c6dcd430cf5c54ab26927bf4dae152bbc9c5c03882a33153501b8483c9febb01e7367452d1b27bb55dade148bec4b80fb70b506b1d16609872958fe5cad40539bfd2a46257ab455f1ef0a1ac0cc88ed9bfcd2072daf4b0fafec4a83849992b7aa72a338704951da7180546c967559f264e0bc0aa5f0d61ba0d1a31c4b4e04f286a4b450aa74cb251b5e914f2560c197f1ca200e6087dfd13ff88d84448d9a14d8198cd01725ab41d5c2f7640a5143e1a7e8f90df96fb2ad68d9e5b958f838503b9d95a21a8fd5c68e4e2f2b9365029ef079310792f5e57daf0c0e90adf0889e2c548b347e79521bac0d8d052586e712b226f8095cfc2e351ab6a9415be244ecdf4f929d12a6e307ae3c0635a9b8e79900ba0d0476d49f83e562e438e57677db7d4ffb2715a3451b191a6ef1a22e2363260a4f00c23f6d9a324505ada8106256f383159e042fb04a2630ce98913d59fcda98f90e78df6c1c9d8dc430f26a562969d9be60cd7bddc19b53cd29499c6616fffaff094dd2874ee03ce4da40361b05e574b448a14a74c7420e427d9de0210d2c6aec09a514e8160c3544780b518fffa70247564dbd06ad9bfdeb06a446aa4f116e9b0c33eb5f3da84cadf8dd1b1fb5eda4768a7f4373e56674ef310aab5b7d3f10740cf248a5d474961ab2d0cdeb005141c2680edc06364c0a35ad6836d932ff7a020c4baf4043a9afd5c84cba90dd3f38b86f8c20faee667ce30d4817cdb0007f2302de60e54da6e2aea6d142baeafbd1382a680621764598988fde58fb045826c909bee29fa94195c1eb6b1be1ae58648f1b5a7245880b7e3aaf460f6702a5fd5b0bcc92f7a141cd5efdeafe710bdeaf3b30fc95c037fb51131c401d4f89cf5aed0fc2c4174e0fdbe444ea81912d8032c30277a94fab5972d758613ae112eba3bf0e529593afb8bfaab09003baf2802427e8ab69fe7c7aefe125cdc7c09d379a9507b0021b68763d32095c553815099ebe1c653b990dd688cb3f3e939c599ebc3200dc4171620d9ffdc138af0daa899ac2d46c0461bba4dc00d97916c0131d54a007f718098dc9382ce2e9467aac5c456286feb5d95c452dcd3a1e857f955bcdab08d53889911481e4c094505faf2f2a6684e7363b5c0c571fbe81cf02f2b834a30edaade2914e85a2aaf4896efab596a6bb5512053e7d67f31629444658d65aca0cc957de3190282a70e61976c8b0903bd3714e827b750d30da1a7b73e7553d740f6c8310f40108d8d2bd3e88664efbad4cbfe3101f510cae4c9b4e72b508004a02c94c3accd9c1c7a5dc2187725781f4967052b98afcefe218c01f2832deee2f0ea42c8c6d82a68f8cb15266f6fec753312b7356260ae0f6e98af921b9600931a6cddd8fb88b634e018011e606747ea0f2333a02c8287a6328201bfb0ffda85f6b48afda20d7d1f97bd91e48a2cdba0467aeac1a2723e84441e0c1da8006e0127f242252864e23d05a0a71fc68d79729131e61d893e5e2593a1c9dc223cdfa3d80fb2bbb4765487a63b4ccc0951a8676da91b7677b3291dd68e1bc18897defa77c70f1de1a9a3a4e91c57b3257469d19ffaeb1ad39c55ef8e3c55b3eeee0ab1ecf91cf47ea42d9c95912e56e8a4125128b76b6383a5b47b5bb3872d7fe875bc549957901c4a31173ac12911a36ee05211d570e500cbeabbcae6fd65205914fa9b2d122030343567e0193b68b3b7ae2b30d300b50b5245502e80068b45155f979ebb42f5b4f41a04e82d1da12e7bec05d8bbd9e09ae4af83ff4bd626303b5263816a8fdd5e38cf5289cb7fd9a477fdc3e4201328b5e1856746f956eb34c1ad5fc0ed79033e3291bbb59de39e1802e7d508e064f31190d2f066bdf0fc78fbbb9137eca243b430de0327aa090883b0b5e29875e460a72d42523f850180848db977f9ea3b0e3451272f4dbe07e2d96238ddbfb5938e18651e9b44df458a70f85d411d4241ba6601d0538991c374ee2929051dc665a9073c819ab72651c6acc305399fd611efe2d85514ef90461067bcfe8b124ca27d1cec884e0e48b18196bf11b8cd6a000a64650e3d344adae30780fa2ba183f8c54bc39f6092d1544281e1fe23395fd3a6f62744d29368b9250abe7c1ede9d2760efe5e44225cbe9b85cd1f6280ba1bb97602e1a04e0d3a932f7af4d10152bc7ec3cef2ad94fa9bef19fae57347cfb310a8c1e85d62bead54f0b49a624ff62abd6d103089ef4de99a3d3d3d72ec2ba75a42a9ed558a155d16da644069f0928a0f241283939e7544f16234ab011f37b710752c56e26f3ad4858d81c1b8d5e970337cbf4d81fdb1b246038b728904b2110998c45cbcd9455fa6a4e7573fc4b2bb3a5c2aee9d929e05ca9da83ff2d6132f4e12bcb16126b685924c08603074667b19f560cfc048a31cf2a132f25f7bd73868626aba139f65aa6d34df526e09950e74c64c4eadb721f669c71f6695098adcc0c4cb09f1b83e0cc119617e255aff2708f7a12834dcc226ef02c5e8acb75f26883116bbde57f72ca9ccd9de713059675d70e7165afff812a544702c8a6ba0b542c64243831be9509672ad11646725c48076d9617cff22f6e2a6a2d5e20d712535cf218ff5ff193b814321e9e523ede2217f51144b74ca544ecac4b4248b9efe59b14eb5ea8971e1fa162981e12c16464d3bdb882ea9b2d2302369e477c82b3a947c0d3ae4092c90b06a17a5fddbe8bb6a8564f0d708725b4b1eb359c7236f25919caa94ce2b4928172459f24c1c9233917d7af08f2a0acd093315adbc5d1fe700fc4b675f073c93b0ee85fc8eb1866d4521ffafc3a3d32ea24e7d7d8d7b0a23d807a2876d9f12ee116acbd81af860b38d56a38a5be3b1e8548902f60e7cc644fcda6d9b3458dd24693193576a08a5b0e11fa98f2ce06293218702b802009c687bc67cff9981378e108e6a57815f0dceba0b38345b8be76a86793d4629675ba37c2c4b1d38c2bbc7dcef1310bc1ac38244e5150b94d78e64867d272c26ae602b742ccc4e0c76898d31d479cdef75fe271d8a068a36235ebef30c3ff0333ba7fbfbfba056d183978c670cd4aa36ff331a54c41b31b864e6ab91c90f3e891307f153b847cdd6dc5b7c1e14dc43e93a810a3e72d4298f01e91928b5a555bfb6150fe0562f955471495e1f88ec80df5ded907cce2850a8a7ec1f39888aeb17f36ed70bb1098572432754e7c3f50879cb93d1e92637f6c7bed04c249afbbf8b71b881c5fc313b255e23ba1acb2cb7fe79f55cd5d883d0fe9b492359e1ced27063b3408b17531d4413123adfecb0daa865502f63f94fc8e1ffc9820052dfade88b98db873ce96e8f4a24b3ee66ff9b6ad6a326e22630120a353521af69cef1c0153125f94be13913548114f31601004c4ccf6884ae158e521f844bcde7626b6f8c72a7e6ff689c001e148e0f8887132a33c1a6798438f682ee03f5ae1c16d5561cf5761d1067fdf8efc13d13df8885fac96ea5032f21f1c34c629dddc4fdd687c438c1cd1b8090e359af75c9f48aacd55467c9cd4bec29776fd3df67d75fae97382355ef45c185a5809622e184e42f91239b76b4d16d1585214f2c139b19b4ab466ab12e4229fab40fe72b90456eba8cb5e4848a2363afc392940163359076f7f84376e03ef6f0820a5ad5d1ee643660cf8f593fad0962571776939b87a4b49b1c27d3d3f1384e4410931b9831328c51233cf8e65fc41a629662ed5d491d6d7f524c8085ec18b6042ffdeceaea78b2d465c42dac88916438033fbea854776e11a9d8f7e7d82117faf256263f1babeb40be9738a0259d549fa677a4e11742b0290efe4e9ef9fd7c107cb585ca6cfa7e116e472e8a7fa6d047c337df487dda36880e47be8229b543ad67f5220f57012d5182737d8790b249a6aa9f3f0a1f43478d637fe066a0b96d5e1532b12bf294e3f5a1b40780ff7c03396badb40cc716f04e35088ad357696259cf8b1209ae5e188777bbf90fadc1d7b42efe7acd251a6b9181e22ff9c7c00d741e6224f38826958ef2c7ba1190a1dbd93d78d72ae138c0fb479ad6d48bb6f077736c3edf69a48d17599d2f99ca34d88abc3e72272b40bab8a57212e6ae2713aeeb006fcd1a7d044acf68ffd2cdf0d23473308673c3aaa7bd599204177392eeac3c4c25cb2adf555b5ee2c5aa9b2f71b8129e8dd80921230dbe3460a79dc11f41d9596700bb04aeec684f3f0333b6e4ddd50f8771b7b1f836a838b262c1278528b42001e4f9b8cc75de8a9f10b7705a1ab8241d193771b056930edb2173abde92432a8f31654083801c495c24b546161cdfb6bdae50cb47c7fd08eed3a260620c734e91f9266777116a5ee94438af3b312a770c6e47121f5fc30570f8e8234dd91f75d15b3fefadfbe47f8aaa3c61da86b0f3ebb65a33e9422f079759483ca56d045d521995d905e130cf1dfe424b6ed19f82e7d356b673cafc0876af7e874341f0f75db71e5c594d123872f2506267ac148dff3fcc73ab6ca60da8d27323433cbaf0f0227fed5542f39ca4e535532e36e96cfd2b7a3f7f6d6c045c9984f4ffbb8725233060d5c10f3940353116a3bcaf63782bbfa4ae52ba1f0165b950c505cf96b89d8c64167a93ece1ad44906f6f09fb052b09a7b9bd85890ab60405a9b9390a3f199326f81891fa42f9ae30d9378264c805d09be4aa7ca90338f2bf5703c5109fe17720dc87e389c930c187f0db83f9d67773c017a8848f07905bc5eaad4f024a772a37d86808cf700b95b4e67dff2f9df80cae43d1b74a0d32c0d8fd18a0835b9607e68669c8feee9a6ca72cec21296e73042f76dbda6908b5d6321e80cd651d69559676aaa0a8c1caa768911411a3f4e830d8dbc3ddc1047027b31e7b5e983b79753e068cf154ee638a3079052f483b55672c7459654409"}'
```

Output:

```json
{
  "status": "success"
}
```

#### import_wallet_request

Request to import wallet using entire blockchain history. This can be associated
with fee to be paid for this service or can be free.

```bash
curl  -w "\n" -X POST http://127.0.0.1:1984/import_wallet_request -d '{"address":"57GLuXxxxAqdm5wT9sFJ4aDQGo2NkanFJXmDoZZbBeUFZ5b7QQ7pJvYjfkvBe9PsiZ4mGY9h7s2uxEiqS945eR6RL2yWikX", "view_key":"5e05a2aae20eafd68443e4d972ea8400cb7309ed85d339104f9f21542e45c403"'}
```

Output when fee is zero

```json
{
  "error": "",
  "import_fee": 0,
  "new_request": true,
  "request_fulfilled": true,
  "status": "Import will start shortly"
}
```

Output when fee is not zero:

```json
{
  "error": "",
  "import_fee": 100000000000,
  "new_request": true,
  "payment_address": "5DUWE29P72Eb8inMa41HuNJG4tj9CcaNKGr6EVSbvhWGJdpDQCiNNYBUNF1oDb8BczU5aD68d3HNKXaEsPq8cvbQLGMBjwL4UQtQYJXrbu",
  "payment_id": "2cf6fef372541dd0",
  "request_fulfilled": false,
  "status": "Payment not yet received"
}
```

#### import_recent_wallet_request

Free import of wallet based on recent blockchain history (e.g., last 10000 blocks)

```bash
curl  -w "\n" -X POST http://127.0.0.1:1984/import_recent_wallet_request -d '{"address":"55rDoHrJrwMUcdbaLYJk571vLAC5eZ8MaCtuDjcsFV2DTwr7R527qS3X8DxuTPsFacMfj3ESNJ9yybvzQjqSHLqsRShPQnJ", "view_key":"3bcf20ea17f8d1198b731bfaa66f7350e4c632a57289d47544ab5d8be43d940a", "no_blocks_to_import":"10000"'}
```

Example output:

```json
{
  "request_fulfilled": true,
  "status": "Updating account with for importing recent txs successeful."
}
```
