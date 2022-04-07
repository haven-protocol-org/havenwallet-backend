//
// Created by marcin on 5/11/15.
//

#include "utils.h"
#include <codecvt>


namespace xmreg
{


/**
 * Get transaction tx using given tx hash. Hash is represent as string here,
 * so before we can tap into the blockchain, we need to pare it into
 * crypto::hash object.
 */
bool
get_tx_pub_key_from_str_hash(Blockchain& core_storage, const string& hash_str, transaction& tx)
{
    crypto::hash tx_hash;
    parse_hash256(hash_str, tx_hash);

    try
    {
        // get transaction with given hash
        tx = core_storage.get_db().get_tx(tx_hash);
    }
    catch (const TX_DNE& e)
    {
        cerr << e.what() << endl;
        return false;
    }

    return true;
}

/**
 * Parse monero address in a string form into
 * cryptonote::account_public_address object
 */



string
print_sig (const signature& sig)
{
    stringstream ss;

    ss << "c: <" << epee::string_tools::pod_to_hex(sig.c) << "> "
       << "r: <" << epee::string_tools::pod_to_hex(sig.r) << ">";

    return ss.str();
}

/**
 * Check if a character is a path seprator
 */
inline bool
is_separator(char c)
{
    // default linux path separator
    const char separator = PATH_SEPARARTOR;

    return c == separator;
}


string
timestamp_to_str_gm(time_t timestamp, const char* format)
{
    const time_t* t = &timestamp;

    const int TIME_LENGTH = 60;

    char str_buff[TIME_LENGTH];

    std::tm tmp;
    gmtime_r(t, &tmp);

    size_t len;

    len = std::strftime(str_buff, TIME_LENGTH, format, &tmp);

    return string(str_buff, len);
}

string
timestamp_to_str_local(time_t timestamp, const char* format)
{

    const int TIME_LENGTH = 60;

    char str_buff[TIME_LENGTH];

    tm *tm_ptr;
    tm_ptr = localtime(&timestamp);

    size_t len;

    len = std::strftime(str_buff, TIME_LENGTH, format, tm_ptr);

    return string(str_buff, len);
}


ostream&
operator<< (ostream& os, const address_parse_info& addr_info)
{
    os << get_account_address_as_str(network_type::MAINNET,
                                     addr_info.is_subaddress,
                                     addr_info.address);
    return os;
}


/*
 * Generate key_image of foran ith output
 */
bool
generate_key_image(const crypto::key_derivation& derivation,
                   const std::size_t i,
                   const crypto::secret_key& sec_key,
                   const crypto::public_key& pub_key,
                   crypto::key_image& key_img)
{

    cryptonote::keypair in_ephemeral;

    if (!crypto::derive_public_key(derivation, i,
                                   pub_key,
                                   in_ephemeral.pub))
    {
        cerr << "Error generating publick key " << pub_key << endl;
        return false;
    }

    try
    {

        crypto::derive_secret_key(derivation, i,
                                  sec_key,
                                  in_ephemeral.sec);
    }
    catch(const std::exception& e)
    {
        cerr << "Error generate secret image: " << e.what() << endl;
        return false;
    }


    try
    {
        crypto::generate_key_image(in_ephemeral.pub,
                                   in_ephemeral.sec,
                                   key_img);
    }
    catch(const std::exception& e)
    {
        cerr << "Error generate key image: " << e.what() << endl;
        return false;
    }

    return true;
}


array<uint64_t, 4>
summary_of_in_out_rct(
        const transaction& tx,
        vector<pair<crypto::public_key, uint64_t>>& output_pub_keys,
        vector<crypto::key_image>& input_key_imgs)
{

    uint64_t xmr_outputs       {0};
    uint64_t xmr_inputs        {0};
    uint64_t mixin_no          {0};
    uint64_t num_nonrct_inputs {0};


    for (const tx_out& txout: tx.vout)
    {
        if ((txout.target.type() != typeid(cryptonote::txout_to_key)) &&
            (txout.target.type() != typeid(cryptonote::txout_offshore)) &&
            (txout.target.type() != typeid(cryptonote::txout_xasset)))
        {
            // push empty pair.
            output_pub_keys.push_back(pair<crypto::public_key, uint64_t>{});
            continue;
        };

        // get tx input key
        crypto::public_key txout_key =
	        (txout.target.type() == typeid(cryptonote::txout_to_key)) 
                ? boost::get<txout_to_key>(txout.target).key
	            : (txout.target.type() == typeid(cryptonote::txout_offshore)) 
                    ? boost::get<txout_offshore>(txout.target).key
	                : boost::get<txout_xasset>(txout.target).key;

        output_pub_keys.push_back(make_pair(txout_key, txout.amount));

        xmr_outputs += txout.amount;
    }

    size_t input_no = tx.vin.size();

    for (size_t i = 0; i < input_no; ++i)
    {

        // get tx input key
        const auto &in = tx.vin[i];

        crypto::key_image k_image;
        uint64_t amount;
        std::vector<uint64_t> key_offsets;

        if (in.type() == typeid(cryptonote::txin_to_key)) {
            k_image = boost::get<cryptonote::txin_to_key>(in).k_image;
            amount = boost::get<cryptonote::txin_to_key>(in).amount;
            key_offsets = boost::get<cryptonote::txin_to_key>(in).key_offsets;
        } else if (in.type() == typeid(cryptonote::txin_offshore)) {
            k_image = boost::get<cryptonote::txin_offshore>(in).k_image;
            amount = boost::get<cryptonote::txin_offshore>(in).amount;
            key_offsets = boost::get<cryptonote::txin_offshore>(in).key_offsets;
        } else if (in.type() == typeid(cryptonote::txin_onshore)) {
            k_image = boost::get<cryptonote::txin_onshore>(in).k_image;
            amount = boost::get<cryptonote::txin_onshore>(in).amount;
            key_offsets = boost::get<cryptonote::txin_onshore>(in).key_offsets;
        } else if (in.type() == typeid(cryptonote::txin_xasset)) {
            k_image = boost::get<cryptonote::txin_xasset>(in).k_image;
            amount = boost::get<cryptonote::txin_xasset>(in).amount;
            key_offsets = boost::get<cryptonote::txin_xasset>(in).key_offsets;
        } else {
            continue;
        }

        xmr_inputs += amount;

        if (amount != 0)
        {
            ++num_nonrct_inputs;
        }

        if (mixin_no == 0)
        {
            mixin_no = key_offsets.size();
        }

        input_key_imgs.push_back(k_image);

    } //  for (size_t i = 0; i < input_no; ++i)


    return {xmr_outputs, xmr_inputs, mixin_no, num_nonrct_inputs};
};


// this version for mempool txs from json
array<uint64_t, 6>
summary_of_in_out_rct(const json& _json)
{
    uint64_t xmr_outputs       {0};
    uint64_t xmr_inputs        {0};
    uint64_t no_outputs        {0};
    uint64_t no_inputs         {0};
    uint64_t mixin_no          {0};
    uint64_t num_nonrct_inputs {0};

    for (const json& vout: _json["vout"])
    {
        xmr_outputs += vout["amount"].get<uint64_t>();
    }

    no_outputs = _json["vout"].size();

    for (const json& vin: _json["vin"])
    {
        uint64_t amount = vin["key"]["amount"].get<uint64_t>();

        xmr_inputs += amount;

        if (amount != 0)
            ++num_nonrct_inputs;
    }

    no_inputs  = _json["vin"].size();

    mixin_no = _json["vin"].at(0)["key"]["key_offsets"].size() - 1;

    return {xmr_outputs, xmr_inputs, no_outputs, no_inputs, mixin_no, num_nonrct_inputs};
};



uint64_t
sum_money_in_outputs(const transaction& tx)
{
    uint64_t sum_xmr {0};

    for (const tx_out& txout: tx.vout)
    {
        sum_xmr += txout.amount;
    }

    return sum_xmr;
}

pair<uint64_t, uint64_t>
sum_money_in_outputs(const string& json_str)
{
    pair<uint64_t, uint64_t> sum_xmr {0, 0};

    json j;

    try
    {
       j = json::parse( json_str);
    }
    catch (std::invalid_argument& e)
    {
        cerr << "sum_money_in_outputs: " << e.what() << endl;
        return sum_xmr;
    }

    for (json& vout: j["vout"])
    {
        sum_xmr.first += vout["amount"].get<uint64_t>();
        ++sum_xmr.second;
    }


    return sum_xmr;
};



uint64_t
sum_money_in_inputs(const transaction& tx)
{
    uint64_t sum_xmr {0};

    size_t input_no = tx.vin.size();

    for (size_t i = 0; i < input_no; ++i)
    {
        // get tx input key
        const auto &in = tx.vin[i];

        uint64_t amount;

        if (in.type() == typeid(cryptonote::txin_to_key)) {
            amount = boost::get<cryptonote::txin_to_key>(in).amount;
        } else if (in.type() == typeid(cryptonote::txin_offshore)) {
            amount = boost::get<cryptonote::txin_offshore>(in).amount;
        } else if (in.type() == typeid(cryptonote::txin_onshore)) {
            amount = boost::get<cryptonote::txin_onshore>(in).amount;
        } else if (in.type() == typeid(cryptonote::txin_xasset)) {
            amount = boost::get<cryptonote::txin_xasset>(in).amount;
        } else {
            continue;
        }

        sum_xmr += amount;
    }

    return sum_xmr;
}

pair<uint64_t, uint64_t>
sum_money_in_inputs(const string& json_str)
{
    pair<uint64_t, uint64_t> sum_xmr {0, 0};

    json j;
    try
    {
        j = json::parse( json_str);
    }
    catch (std::invalid_argument& e)
    {
        cerr << "sum_money_in_outputs: " << e.what() << endl;
        return sum_xmr;
    }

    for (json& vin: j["vin"])
    {
        sum_xmr.first += vin["key"]["amount"].get<uint64_t>();
        ++sum_xmr.second;
    }

    return sum_xmr;
};

array<uint64_t, 2>
sum_money_in_tx(const transaction& tx)
{
    array<uint64_t, 2> sum_xmr;

    sum_xmr[0] = sum_money_in_inputs(tx);
    sum_xmr[1] = sum_money_in_outputs(tx);

    return sum_xmr;
};


array<uint64_t, 2>
sum_money_in_txs(const vector<transaction>& txs)
{
    array<uint64_t, 2> sum_xmr {0,0};

    for (const transaction& tx: txs)
    {
        sum_xmr[0] += sum_money_in_inputs(tx);
        sum_xmr[1] += sum_money_in_outputs(tx);
    }

    return sum_xmr;
};


uint64_t
sum_fees_in_txs(const vector<transaction>& txs)
{
    uint64_t fees_sum {0};

    for (const transaction& tx: txs)
    {
        fees_sum += get_tx_fee(tx);
    }

    return fees_sum;
}

uint64_t
get_mixin_no(const transaction& tx)
{
    uint64_t mixin_no {0};

    size_t input_no = tx.vin.size();

    for (size_t i = 0; i < input_no; ++i)
    {

        const auto &in = tx.vin[i];

        std::vector<uint64_t> key_offsets;

        if (in.type() == typeid(cryptonote::txin_to_key)) {
            key_offsets = boost::get<cryptonote::txin_to_key>(in).key_offsets;
        } else if (in.type() == typeid(cryptonote::txin_offshore)) {
            key_offsets = boost::get<cryptonote::txin_offshore>(in).key_offsets;
        } else if (in.type() == typeid(cryptonote::txin_onshore)) {
            key_offsets = boost::get<cryptonote::txin_onshore>(in).key_offsets;
        } else if (in.type() == typeid(cryptonote::txin_xasset)) {
            key_offsets = boost::get<cryptonote::txin_xasset>(in).key_offsets;
        } else {
            continue;
        }

        mixin_no = key_offsets.size();

        // look for first mixin number.
        // all inputs in a single transaction have same number
        if (mixin_no > 0)
        {
            break;
        }
    }

    return mixin_no;
}
vector<uint64_t>
get_mixin_no(const string& json_str)
{
    vector<uint64_t> mixin_no;

    json j;

    try
    {
        j = json::parse(json_str);

        mixin_no.push_back(j["vin"].at(0)["key"]["key_offsets"].size());
    }
    catch (std::invalid_argument& e)
    {
        cerr << "get_mixin_no: " << e.what() << endl;
        return mixin_no;
    }

    return mixin_no;
}



vector<uint64_t>
get_mixin_no_in_txs(const vector<transaction>& txs)
{
    vector<uint64_t> mixin_no;

    for (const transaction& tx: txs)
    {
        mixin_no.push_back(get_mixin_no(tx));
    }

    return mixin_no;
}


vector<crypto::key_image>
get_key_images(const transaction& tx)
{
    vector<crypto::key_image> key_images;

    size_t input_no = tx.vin.size();

    for (size_t i = 0; i < input_no; ++i)
    {

        // get tx input key
        const auto &in = tx.vin[i];
        crypto::key_image k_image;

        if (in.type() == typeid(cryptonote::txin_to_key)) {
            k_image = boost::get<cryptonote::txin_to_key>(in).k_image;
        } else if (in.type() == typeid(cryptonote::txin_offshore)) {
            k_image = boost::get<cryptonote::txin_offshore>(in).k_image;
        } else if (in.type() == typeid(cryptonote::txin_onshore)) {
            k_image = boost::get<cryptonote::txin_onshore>(in).k_image;
        } else if (in.type() == typeid(cryptonote::txin_xasset)) {
            k_image = boost::get<cryptonote::txin_xasset>(in).k_image;
        } else {
            continue;
        }

        key_images.push_back(k_image);
    }

    return key_images;
}

bool
get_payment_id(const vector<uint8_t>& extra,
               crypto::hash& payment_id,
               crypto::hash8& payment_id8)
{
    payment_id = null_hash;
    payment_id8 = null_hash8;

    std::vector<tx_extra_field> tx_extra_fields;

    if(!parse_tx_extra(extra, tx_extra_fields))
    {
        return false;
    }

    tx_extra_nonce extra_nonce;

    if (find_tx_extra_field_by_type(tx_extra_fields, extra_nonce))
    {
        // first check for encrypted id and then for normal one
        if(get_encrypted_payment_id_from_tx_extra_nonce(extra_nonce.nonce, payment_id8))
        {
            return true;
        }
        else if (get_payment_id_from_tx_extra_nonce(extra_nonce.nonce, payment_id))
        {
            return true;
        }
    }

    return false;
}


// just a copy from bool
// device_default::encrypt_payment_id(crypto::hash8 &payment_id, const crypto::public_key &public_key, const crypto::secret_key &secret_key)
bool
encrypt_payment_id(crypto::hash8 &payment_id,
                   const crypto::public_key &public_key,
                   const crypto::secret_key &secret_key)
{
    #define ENCRYPTED_PAYMENT_ID_TAIL 0x8d

    crypto::key_derivation derivation;
    crypto::hash hash;
    char data[33]; /* A hash, and an extra byte */

    if (!generate_key_derivation(public_key, secret_key, derivation))
        return false;

    memcpy(data, &derivation, 32);
    data[32] = ENCRYPTED_PAYMENT_ID_TAIL;
    cn_fast_hash(data, 33, hash);

    for (size_t b = 0; b < 8; ++b)
        payment_id.data[b] ^= hash.data[b];

    return true;
}


array<size_t, 5>
timestamp_difference(uint64_t t1, uint64_t t2)
{

    uint64_t timestamp_diff = t1 - t2;

    // calculate difference of timestamps from current block to the mixin one
    if (t2 > t1)
    {
        timestamp_diff = t2 - t1;
    }

    uint64_t time_diff_years = timestamp_diff / 31536000;

    timestamp_diff -=  time_diff_years * 31536000;

    uint64_t time_diff_days = timestamp_diff / 86400;

    timestamp_diff -=  time_diff_days * 86400;

    uint64_t time_diff_hours = timestamp_diff / 3600;

    timestamp_diff -=  time_diff_hours * 3600;

    uint64_t time_diff_minutes = timestamp_diff / 60;

    timestamp_diff -=  time_diff_minutes * 60;

    uint64_t time_diff_seconds = timestamp_diff ;

    return array<size_t, 5> {time_diff_years, time_diff_days,
                             time_diff_hours, time_diff_minutes,
                             time_diff_seconds};

};


string
read(string filename)
{
   if (!bf::exists(bf::path(filename)))
   {
       cerr << "File does not exist: " << filename << endl;
       return string();
   }

    std::ifstream t(filename);
    return string(std::istreambuf_iterator<char>(t),
                  std::istreambuf_iterator<char>());
}

pair<string, double>
timestamps_time_scale(const vector<uint64_t>& timestamps,
                      uint64_t timeN,
                      uint64_t resolution,
                      uint64_t time0)
{
    string empty_time =  string(resolution, '_');

    size_t time_axis_length = empty_time.size();

    uint64_t interval_length = timeN-time0;

    double scale = double(interval_length) / double(time_axis_length);

    for (const auto& timestamp: timestamps)
    {

        if (timestamp < time0 || timestamp > timeN)
        {
            cout << "Out of range" << endl;
            continue;
        }

        uint64_t timestamp_place = double(timestamp-time0)
                         / double(interval_length)*(time_axis_length - 1);

        empty_time[timestamp_place + 1] = '*';
    }

    return make_pair(empty_time, scale);
}

// bool
// decode_ringct(const rct::rctSig& rv,
//               const crypto::public_key &pub,
//               const crypto::secret_key &sec,
//               unsigned int i,
//               rct::key & mask,
//               uint64_t & amount)
// {
//     crypto::key_derivation derivation;

//     bool r = crypto::generate_key_derivation(pub, sec, derivation);

//     if (!r)
//     {
//         cerr <<"Failed to generate key derivation to decode rct output " << i << endl;
//         return false;
//     }

//     return decode_ringct(rv, derivation, i, mask, amount);
// }


// bool
// decode_ringct(rct::rctSig const& rv,
//               crypto::key_derivation const& derivation,
//               unsigned int i,
//               rct::key& mask,
//               uint64_t& amount)
// {
//     try
//     {
//         crypto::secret_key scalar1;

//         crypto::derivation_to_scalar(derivation, i, scalar1);

//         switch (rv.type)
//         {
//             case rct::RCTTypeSimple:
//             case rct::RCTTypeBulletproof:
//                 amount = rct::decodeRctSimple(rv,
//                                               rct::sk2rct(scalar1),
//                                               i,
//                                               mask,
//                                               hw::get_device("default"));
//                 break;
//             case rct::RCTTypeFull:
//                 amount = rct::decodeRct(rv,
//                                         rct::sk2rct(scalar1),
//                                         i,
//                                         mask,
//                                         hw::get_device("default"));
//                 break;
//             default:
//                 cerr << "Unsupported rct type: " << rv.type << '\n';
//                 return false;
//         }
//     }
//     catch (...)
//     {
//         cerr << "Failed to decode input " << i << '\n';
//         return false;
//     }

//     return true;
// }


bool
url_decode(const std::string& in, std::string& out)
{
    out.clear();
    out.reserve(in.size());
    for (std::size_t i = 0; i < in.size(); ++i)
    {
        if (in[i] == '%')
        {
            if (i + 3 <= in.size())
            {
                int value = 0;
                std::istringstream is(in.substr(i + 1, 2));
                if (is >> std::hex >> value)
                {
                    out += static_cast<char>(value);
                    i += 2;
                }
                else
                {
                    return false;
                }
            }
            else
            {
                return false;
            }
        }
        else if (in[i] == '+')
        {
            out += ' ';
        }
        else
        {
            out += in[i];
        }
    }
    return true;
}

map<std::string, std::string>
parse_crow_post_data(const string& req_body)
{
    map<std::string, std::string> body;

    vector<string> vec;
    string tmp;
    bool result = url_decode(req_body, tmp);
    if (result)
    {
        boost::algorithm::split(vec, tmp, [](char x) {return x == '&'; });
        for(auto &it : vec)
        {
            auto pos = it.find("=");
            if (pos != string::npos)
            {
                body[it.substr(0, pos)] = it.substr(pos + 1);
            }
            else
            {
                break;
            }
        }
    }
    return body;
}



//string
//xmr_amount_to_str(const uint64_t& xmr_amount, string format)
//{
    //return fmt::format(format, XMR_AMOUNT(xmr_amount));
//}



/**
* Check if given output (specified by output_index)
* belongs is ours based
* on our private view key and public spend key
*/
bool
is_output_ours(const size_t& output_index,
               const transaction& tx,
               const public_key& pub_tx_key,
               const secret_key& private_view_key,
               const public_key& public_spend_key)
{
    // public transaction key is combined with our viewkey
    // to create, so called, derived key.
    key_derivation derivation;

    if (!generate_key_derivation(pub_tx_key, private_view_key, derivation))
    {
        cerr << "Cant get dervied key for: "  << "\n"
             << "pub_tx_key: " << pub_tx_key  << " and "
             << "prv_view_key" << private_view_key << endl;

        return false;
    }


    // get the tx output public key
    // that normally would be generated for us,
    // if someone had sent us some xmr.
    public_key pubkey;

    derive_public_key(derivation,
                      output_index,
                      public_spend_key,
                      pubkey);

    //cout << "\n" << tx.vout.size() << " " << output_index << endl;

    // get tx output public key
    const auto &o = tx.vout[output_index];
    crypto::public_key txout_key =
        (o.target.type() == typeid(cryptonote::txout_to_key)) 
            ? boost::get<txout_to_key>(o.target).key
            : (o.target.type() == typeid(cryptonote::txout_offshore)) 
                ? boost::get<txout_offshore>(o.target).key
                : boost::get<txout_xasset>(o.target).key;


    if (txout_key == pubkey)
    {
        return true;
    }

    return false;
}


string
get_human_readable_timestamp(uint64_t ts)
{
    char buffer[64];
    if (ts < 1234567890)
        return "<unknown>";

    time_t tt = ts;

    struct tm tm;

    gmtime_r(&tt, &tm);

    strftime(buffer, sizeof(buffer), "%Y-%m-%d %I:%M:%S ", &tm);

    return std::string(buffer);
}

string
make_hash(const string& in_str)
{
    crypto::hash vk_hash;
    crypto::cn_fast_hash(in_str.c_str(), in_str.length(), vk_hash);
    return pod_to_hex(vk_hash);
}


bool
hex_to_tx_blob(string const& tx_hex, string& tx_blob)
{
    return epee::string_tools::parse_hexstr_to_binbuff(tx_hex, tx_blob);
}

bool
hex_to_complete_block(string const& cblk_str,
                      block_complete_entry& cblk)
{
    cryptonote::blobdata cblk_blob;

    if (!epee::string_tools::parse_hexstr_to_binbuff(
                cblk_str, cblk_blob))
        return false;

    if (!epee::serialization::load_t_from_binary(cblk, cblk_blob))
        return false;

    return true;
}

bool
hex_to_complete_block(vector<string> const& cblks_str,
                      vector<block_complete_entry>& cblks)
{
    for (auto const& cblk_str: cblks_str)
    {

        block_complete_entry cblk;

        if (!hex_to_complete_block(cblk_str, cblk))
            return false;

        cblks.push_back(cblk);
    }

    return true;
}

bool
blocks_and_txs_from_complete_blocks(
        vector<block_complete_entry> const& cblks,
        vector<block>& blocks,
        vector<transaction>& transactions)
{


    for (auto const& cblk: cblks)
    {
        block blk;

        if (!parse_and_validate_block_from_blob(cblk.block, blk))
            return false;

        blocks.push_back(blk);

        // first is miner_tx
        transactions.push_back(blk.miner_tx);

        vector<transaction> txs;

        for (auto const& tx_blob: cblk.txs)
        {
            transaction tx;

            if (!parse_and_validate_tx_from_blob(tx_blob.blob, tx))
                return false;

            txs.push_back(tx);
        }

        // now normal txs
        transactions.insert(transactions.end(),
                            txs.begin(), txs.end());
    }

    return true;
}

bool
output_data_from_hex(
        string const& out_data_hex,
        std::map<vector<uint64_t>,
                 vector<cryptonote::output_data_t>>&
                     outputs_data_map)
{
    // key: vector of absolute_offsets and associated amount (last value),
    // value: vector of output_info_of_mixins as string
    std::map<vector<uint64_t>, vector<string>> outputs_data_map_str;

    try
    {
        string out_data_blob;

        if (!epee::string_tools::parse_hexstr_to_binbuff(
                    out_data_hex, out_data_blob))
            return false;

        std::stringstream iss;
        iss << out_data_blob;
        boost::archive::portable_binary_iarchive archive(iss);
        archive >> outputs_data_map_str;

        for (auto const& kv: outputs_data_map_str)
        {
            auto const& absolute_offsets = kv.first;

            for (string const& s: kv.second)
            {
                cryptonote::output_data_t out_data;

                if (!hex_to_pod(s, out_data))
                {
                    cerr << "hex_to_pod faild in output_data_from_hex\n";
                    return false;
                }

                //cout << "\n absolute_offsets (last value is amount): ";
                //for (auto& v: absolute_offsets)
                //    cout << v << ", ";
                //cout << '\n';

                outputs_data_map[absolute_offsets].push_back(out_data);
            }
        }
    }
    catch (...)
    {
        cerr << "deserialization faild in output_data_from_hex\n";
        return false;
    }

    return true;
}


bool
populate_known_outputs_from_csv(
        string const& csv_file,
        std::unordered_map<public_key, uint64_t>& known_outputs,
        bool skip_first_line)
{

    std::ifstream input(csv_file);

    if (!input.is_open())
    {
        cerr << "Cant open: " << csv_file << '\n';
        return false;
    }

    string line;

    while(getline(input, line))
    {
       if (skip_first_line)
       {
           skip_first_line = false;
           continue;
       }
       vector<string> vec;

       boost::algorithm::split(vec, line, boost::is_any_of(","));

       uint64_t amount;
       string  out_public_key;

       try
       {
          amount  = boost::lexical_cast<uint64_t>(vec.at(7));
          out_public_key = vec.at(8);
       }
       catch (std::exception const& e)
       {
           cerr << e.what() << endl;
           return false;
       }

       public_key out_pk;

       if (!hex_to_pod(out_public_key, out_pk))
       {
           cerr << "hex_to_pod failed in output_data_from_hex\n";
           return false;
       }

       auto it = known_outputs.find(out_pk);

       if (it != known_outputs.end())
       {
           cerr << "csv has duplicate out_public_key\n";
           return false;
       }

       known_outputs.insert({out_pk, amount});
    }

    return true;

}

    void
    add_to_total(json & j_totals, string asset_type, uint64_t amount)
    {
        uint64_t total = stoull(j_totals[asset_type].get<std::string>());
        total += amount;
        j_totals[asset_type] = std::to_string(total);
    }

    json
    merge_totals(json j_totalsA, json j_totalsB)
    {
        json j_totals = {};

        for(auto& [asset_type, amount] : j_totalsA.items()) 
        {
            uint64_t total =  stoull(amount.get<std::string>()) + stoull(j_totalsB[asset_type].get<std::string>());
            j_totals[asset_type] = std::to_string(total);
        }

        return j_totals;
    }

    json
    init_totals()
    {
        return json{{    "XAG",        "0"      },
                    {    "XAU",        "0"      },
                    {    "XAUD",       "0"      },
                    {    "XBTC",       "0"      },
                    {    "XCAD",       "0"      },
                    {    "XCHF",       "0"      },
                    {    "XCNY",       "0"      },
                    {    "XEUR",       "0"      },
                    {    "XGBP",       "0"      },
                    {    "XJPY",       "0"      },
                    {    "XNOK",       "0"      },
                    {    "XNZD",       "0"      },
                    {    "XUSD",       "0"      },
                    {    "XHV",        "0"      }};
    }

}

