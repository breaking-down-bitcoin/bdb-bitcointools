# -*- coding: utf-8 -*-
'''
Block Explorer			https://www.blocktrail.com/tBTC/tx/3c2a93844cb0df2ebfae65afbba3c73206c4e60797e59401c3860f3c521af916
Send to pub address 	mnrVtF8DWjMu839VW3rBfgYaAfKk8983Xf 0.05 TBTC
Mine pub address 		mo3kHhHn6ixsXy8LGcdY2zW2QkE8FmhsFH 0.04 TBTC
'''
from binascii import hexlify, unhexlify
from pycoin.encoding import a2b_hashed_base58
from hashlib import sha256
from random import randint
from pycoin.ecdsa import generator_secp256k1 as g
from pycoin.tx.script.der import sigencode_der
from pycoin.encoding import b2a_hashed_base58,hash160

def prepend_byte_len_hex(string_of_bytes):
    length = len(string_of_bytes)
    byte_len = length / 2
    hex_of_byte_len = str(hex(int(byte_len)))
    return hex_of_byte_len[2:] + string_of_bytes


if __name__ == '__main__':
    prev_hash = '3f7352324c97313dfb36c7d2234aef84708ab48739aee4a38b6ffc884dcdeb76'		#TX ID
    print('Prev hash: {}'.format(prev_hash))

    prev_hash_le = hexlify(unhexlify(prev_hash)[::-1])	#LE TX ID
    print('Prev hash LE: {}'.format(prev_hash_le.decode()))

    print()


    # ADDRESS TO PUB KEY IN HEX

    address_send_to = 'mfZ18J7nP5t4L1F79Mu9jhVzMfBxDKifLk'			#Send TO ADDRESS
    print('Send to address: {}'.format(address_send_to))

    pub_key_send_to_hex = hexlify(a2b_hashed_base58(address_send_to)[1:])
    print('Send to pub key hex: {}'.format(pub_key_send_to_hex))

    address_mine = 'mo3kHhHn6ixsXy8LGcdY2zW2QkE8FmhsFH'				#MY ADDRESS
    print('My address: {}'.format(address_mine))

    pub_key_mine_hex = hexlify(a2b_hashed_base58(address_mine)[1:])
    print('My pub key hex: {}'.format(pub_key_mine_hex))

    print()



    # BUILD TX

    ver = '01000000'
    print('Ver: {}'.format(ver))

    num_input = '01'
    print('Number of inputs: {}'.format(num_input))

    print('Prev tx hash LE: {}'.format(prev_hash_le.decode()))

    prev_index = '00000000'
    print('Prev tx output index: {}'.format(prev_index))

    scriptpubkey_prev_tx = '1976a914' + str(pub_key_mine_hex.decode()) + '88ac'

    sighash_all_postsign = '01' # not used for signing, appended to scriptsig after signing

    seq = 'ffffffff'
    print('Sequence: {}'.format(seq))

    num_output = '02'
    print('Number of outputs: {}'.format(num_output))

    val_send = '8096980000000000'   # Little Endian FOrmat of 10,000,000 satoshis in hex
    print('Value to send: {}'.format(val_send))

    script_pub_key_send_to = '1976a914' + str(pub_key_send_to_hex.decode()) + '88ac'
    print('ScripPubKey for send: {}'.format(script_pub_key_send_to))

    val_change = 'd837470300000000'     # Little Endian FOrmat of 5,400,000 satoshis in hex
    print('Value to return (change): {}'.format(val_change))

    scriptpubkey_change_addr = '1976a914' + str(pub_key_mine_hex.decode()) + '88ac'
    print('ScriptPubKey for return (change): {}'.format(scriptpubkey_change_addr))

    locktime = '00000000'
    print('Locktime: {}'.format(locktime))

    sighash_all_presign = '01000000' # Required to be at end of transaction at signing time, removed after signing
    print('SIGHASH_ALL: {}'.format(sighash_all_presign))

    tx_to_hash = (ver + num_input + prev_hash_le.decode() + prev_index + scriptpubkey_prev_tx + seq + num_output + val_send + script_pub_key_send_to + val_change + scriptpubkey_change_addr + locktime + sighash_all_presign)

    print(tx_to_hash)

    # Determine pubkey from secret
    secret = 22334455
    x, y = (secret * g).pair()
    pub = g.__class__(g.curve(), x, y)
    hex_x = hex(x)
    print('hex of x: {}'.format(hex_x))
    hex_x = hex_x[2:]
    print('hex of x minus 2 chars: {}'.format(hex_x))
    # hex_y = hex(y)
    # hex_y = hex_y[2:]
    # y % 2 # odd

    # compressed and y % 2 =1 so odd -> preprend 03
    pub_key_mine = '03' + hex_x #03 if odd and 02 if even
    print('Sec formatted pubkey: {}'.format(pub_key_mine))
    # sec_bin = unhexlify(sec)
    # h160 = hash160(sec_bin)
    # address_unicode = b2a_hashed_base58(chr(0x6f) + h160)
    # address = str(address_unicode)

    # scriptSig, signing the above transaction
    # tx_to_hash = '0x' + tx_to_hash
    tx_to_hash = unhexlify(tx_to_hash)
    print('Transaction to Hash: {}'.format(tx_to_hash))
    zraw = sha256(sha256(tx_to_hash).digest()).digest()
    print('Zraw: {}'.format(zraw))

    z = int(hexlify(zraw), 16)
    print('z: {}'.format(z))

    print('Secret: {}'.format(secret))

    n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141  #CONSTANT
    print('n: {}'.format(n))

    k = randint(0, 2**256)
    print('k: {}'.format(k))

    r = (k*g).pair()[0]
    print('r: {}'.format(r))

    s = (z+r*secret) * pow(k, n-2, n) % n
    print('s: {}'.format(s))

    print('s less than n/2: {}'.format(s < n/2))

    s_sig = hexlify(sigencode_der(r,s)) #'3044022046536719d9dadf20a5933bcfa44995dfb5e0ef8f03dc2008a2e49111060909b40220648337a31f15fd5711ae25a9f3a8b68f4f05021254fb9566663fad86b6a2c870'
    print('s_sig: {}'.format(s_sig.decode()))

    r_hex = hex(r)  #'0x46536719d9dadf20a5933bcfa44995dfb5e0ef8f03dc2008a2e49111060909b4'
    print('r_hex: {}'.format(r_hex))

    s_hex = hex(s)	#'0x648337a31f15fd5711ae25a9f3a8b68f4f05021254fb9566663fad86b6a2c870'
    print('s_hex: {}'.format(s_hex))


    # THE END

    trans_hex = (ver + num_input + prev_hash_le.decode() + prev_index + prepend_byte_len_hex(prepend_byte_len_hex(s_sig.decode() + sighash_all_postsign) + prepend_byte_len_hex(pub_key_mine)) + seq + num_output + val_send + script_pub_key_send_to + val_change + scriptpubkey_change_addr + locktime)
    print()
    print('Final transaction: {}'.format(trans_hex))

    print(ver + '\n' + num_input + '\n' + prev_hash_le.decode() + '\n' + prev_index + '\n' + prepend_byte_len_hex(prepend_byte_len_hex(s_sig.decode() + sighash_all_postsign) + prepend_byte_len_hex(pub_key_mine)) + '\n' + seq + '\n' + num_output + '\n' + val_send + '\n' + script_pub_key_send_to + '\n' + val_change + '\n' + scriptpubkey_change_addr + '\n' + locktime)

