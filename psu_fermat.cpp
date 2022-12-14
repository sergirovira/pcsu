#include <random>
#include "openfhe.h"

using namespace lbcrypto;


/// @brief This computes x^y (mod p) with the fast exponentiation algorithm
/// @param base base of the power
/// @param exp exponent of the power
/// @param cryptoContext crypto context of the used scheme
/// @param keyPair pair of keys 
/// @param n upper bound on the size of the sets
/// @return returns a ciphertext containing the result of base^exp (mod p)
Ciphertext<DCRTPoly>  exponentiation(Ciphertext<DCRTPoly> base,
                        long int exp, CryptoContext<DCRTPoly> cryptoContext, KeyPair<DCRTPoly> keyPair, size_t n)
{
    
    std::vector<int64_t> vectorOfInts1;

    for (size_t i = 0; i < n*n; ++i) {
        vectorOfInts1.push_back(1);
    }

    Plaintext plaintext1 = cryptoContext->MakePackedPlaintext(vectorOfInts1);

    auto t = cryptoContext->Encrypt(keyPair.publicKey, plaintext1);

    while (exp > 0)
    {
        if (exp % 2 != 0) {
            t = cryptoContext->EvalMult(t, base);
        }

        base = cryptoContext->EvalMult(base, base);
        exp /= 2;
    }

    return t;
}

/// @brief this generates the rotated plaintext of a set 
/// @param list vector containing the elements of the set
/// @param cryptoContext crypto context of the used scheme
/// @param n upper bound on the size of the sets
/// @return returns a plaintext containing n rotated copies of the set, one for each possible cyclic rotation of the set
Plaintext get_rotated_plaintext(std::vector<int64_t> list, CryptoContext<DCRTPoly> cryptoContext, size_t n){
    for (size_t i = list.size(); i < n; ++i) list.push_back(0); //padding
    
    std::vector<int64_t> rotated_list;
    
    for (size_t i = 0; i < n; ++i) {
        for (size_t j = i*n; j < (i+1)*n; ++j) { 
            rotated_list.push_back(list[(j-i)%n]);
        }
    }

    Plaintext ptxt = cryptoContext->MakePackedPlaintext(rotated_list);

    return ptxt;
}

/// @brief this generates a plaintext containing n copies of the set
/// @param list vector containing the elements of the set
/// @param cryptoContext crypto context of the used scheme
/// @param n upper bound on the size of the sets
/// @return returns a plaintext containing n copies of the set
Plaintext get_non_rotated_plaintext(std::vector<int64_t> list, CryptoContext<DCRTPoly> cryptoContext, size_t n){
    for (size_t i = list.size(); i < n; ++i) list.push_back(0); //padding
    std::vector<int64_t> rotated_list;
    
    for (size_t i = 0; i < n; ++i) {
        for (size_t j = 0; j < n; ++j) { 
            rotated_list.push_back(list[j]);
        }
    }

    Plaintext ptxt = cryptoContext->MakePackedPlaintext(rotated_list);
    
    return ptxt;
}

/// @brief this generates a plaintext containing the given list
/// @param list vector containing the elements to be encoded in the plaintext
/// @param cryptoContext crypto context of the used scheme
/// @return returns a plaintext containing the list
Plaintext get_simple_plaintext(std::vector<int64_t> list, CryptoContext<DCRTPoly> cryptoContext) {
    Plaintext ptxt = cryptoContext->MakePackedPlaintext(list);

    return ptxt;
}

/// @brief This computes PSU(a, b) over encrypted sets
/// @param set_a rotated ciphertext of the first set to encrypt
/// @param set_b ciphertext containing n copies of the second set
/// @param cryptoContext crypto context of the used scheme
/// @param keyPair pair of keys 
/// @param n upper bound on the size of the sets
/// @return returns a ciphertext containing encryptions of 0's and/or 1's
Ciphertext<DCRTPoly> encrypted_psu(Ciphertext<DCRTPoly> set_a, Ciphertext<DCRTPoly> set_b, long int exp, CryptoContext<DCRTPoly> cryptoContext, KeyPair<DCRTPoly> keyPair, size_t n) {
    auto ciphertext_sub = cryptoContext->EvalSub(set_a, set_b);
    auto ciphertext_fermat = exponentiation(ciphertext_sub, exp, cryptoContext, keyPair, n);

    return ciphertext_fermat;
}

/// @brief This collapses the n*n list Dec(PSU(a, b)) into an n list
/// @param list decrypted output of PSU
/// @param cryptoContext crypto context of the used scheme
/// @param n upper bound on the size of the sets
/// @return returns a plaintext containing a list of size n with 0's and/or 1's
Plaintext MultiplyMany(Plaintext list, CryptoContext<DCRTPoly> cryptoContext, size_t n) {
    std::vector<int64_t> rotated_list;
    rotated_list = list->GetPackedValue();

    std::vector<int64_t> vec_psu(n, 1);
    for (size_t i = 0; i < n; ++i) {
        for (size_t j = i; j < n*n; j += n) {
            if (rotated_list[j] == 0) vec_psu[i] = 0;
        }
    }

    Plaintext psu = cryptoContext->MakePackedPlaintext(vec_psu);

    return psu;
}

int main() {

    //parameter generation and context setup
    size_t set_size = 124;
    //128 classical security bits
    CCParams<CryptoContextBFVRNS> parameters;
    parameters.SetPlaintextModulus(65537);
    parameters.SetMultiplicativeDepth(20); 
    parameters.SetMaxRelinSkDeg(3);
    parameters.SetMultiplicationTechnique(HPS);

    CryptoContext<DCRTPoly> cryptoContext = GenCryptoContext(parameters);
    cryptoContext->Enable(PKE);
    cryptoContext->Enable(KEYSWITCH);
    cryptoContext->Enable(LEVELEDSHE);
    cryptoContext->Enable(ADVANCEDSHE);

    KeyPair<DCRTPoly> keyPair;
    keyPair = cryptoContext->KeyGen();

    SecurityLevel securitylevel = parameters.GetSecurityLevel();
    std::cout << "Security level of " << securitylevel << " bits" << std::endl;

    const size_t exp = 65536;

    //generate the relinearization key
    cryptoContext->EvalMultKeysGen(keyPair.secretKey);

    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> distrib(1, 1 << 13); 

    const size_t n_parties = 3;

    //generate one random set for each party
    std::vector<std::vector<int64_t>> parties(n_parties);
    std::vector<std::set<int64_t>> set_parties(n_parties);
    
    for (size_t i = 0; i < n_parties; ++i) {
        for (size_t j = 0; j < set_size; ++j) {
            set_parties[i].insert(distrib(gen));
        }
    }

    for (size_t i = 0; i < n_parties; ++i) {
        for (auto it = set_parties[i].begin(); it != set_parties[i].end(); ++it) {
            parties[i].push_back(*it);
        }
    }
    
    //to prevent cardinality leakage, we redefine set_size as an upper_bound on the set sizes
    distrib = std::uniform_int_distribution<int>(1, 10);
    set_size += distrib(gen);

    //************PSU of 2 parties***************
    
    //both parties encode their databases in the required format
    Plaintext a_ = get_rotated_plaintext(parties[0], cryptoContext, set_size);
    Plaintext b_ = get_non_rotated_plaintext(parties[1], cryptoContext, set_size);
    
    //both parties encrypt their databases
    auto a = cryptoContext->Encrypt(keyPair.publicKey, a_);
    auto b = cryptoContext->Encrypt(keyPair.publicKey, b_);
    //a and b are sent to the server

    //the server computes psu over the encrypted databases
    Ciphertext<DCRTPoly> psu_tt = encrypted_psu(a, b, exp, cryptoContext, keyPair, set_size);
    //the server sends this to the client

    //the client decrypts the result
    Plaintext psu_t;
    cryptoContext->Decrypt(keyPair.secretKey, psu_tt, &psu_t);
    Plaintext psu = MultiplyMany(psu_t, cryptoContext, set_size);
    auto d = cryptoContext->Encrypt(keyPair.publicKey, psu); 
    //the client sends the list containing encryptions of 0's and/or 1's to the server
    
    //second party encodes and encrypts a simple copy of its database
    Plaintext B_ = get_simple_plaintext(parties[1], cryptoContext);
    auto B = cryptoContext->Encrypt(keyPair.publicKey, B_);
    //this is sent to the server

    //the server computes the product
    auto c = cryptoContext->EvalMult(B, d); 
    //psu of 2 parties finished

    //***************PSU of 3 parties***************

    //l_b will be the lists conaining encryptions of 0's and/or 1's to be multiplied by B's database
    //l_c will be the lists conaining encryptions of 0's and/or 1's to be multiplied by C's database
    Ciphertext<DCRTPoly> l_b, l_c; 

    //parties encode their databases in the required format
    a_ = get_rotated_plaintext(parties[0], cryptoContext, set_size);
    b_ = get_non_rotated_plaintext(parties[1], cryptoContext, set_size);
    auto b__ = get_rotated_plaintext(parties[1], cryptoContext, set_size);
    Plaintext c_ = get_non_rotated_plaintext(parties[2], cryptoContext, set_size);

    //parties encrypt their databases
    a = cryptoContext->Encrypt(keyPair.publicKey, a_);
    b = cryptoContext->Encrypt(keyPair.publicKey, b_);
    auto b_rot = cryptoContext->Encrypt(keyPair.publicKey, b__);
    c = cryptoContext->Encrypt(keyPair.publicKey, c_);
    //a, b, b_rot and c are sent to the server

    //parties encode and encrypt one simple copy of their databases
    Plaintext A_ = get_simple_plaintext(parties[0], cryptoContext);
    auto A = cryptoContext->Encrypt(keyPair.publicKey, A_);

    B_ = get_simple_plaintext(parties[1], cryptoContext);
    B = cryptoContext->Encrypt(keyPair.publicKey, B_);

    Plaintext C_ = get_simple_plaintext(parties[2], cryptoContext);
    auto C = cryptoContext->Encrypt(keyPair.publicKey, C_);
    //A, B and C are sent to the server

    //B*PSU(A, B)
    //the server computes psu(a, b) over the encrypted databases
    psu_tt = encrypted_psu(a, b, exp, cryptoContext, keyPair, set_size);
    //the server sends this to the client and the client decrypts the result
    cryptoContext->Decrypt(keyPair.secretKey, psu_tt, &psu_t);
    psu = MultiplyMany(psu_t, cryptoContext, set_size);
    l_b = cryptoContext->Encrypt(keyPair.publicKey, psu);
    //the client sends the list containing encryptions of 0's and/or 1's to the server
    B = cryptoContext->EvalMult(B, l_b);

    //l_c_a=PSU(A, C)
    //the server computes psu(a, c) over the encrypted databases
    psu_tt = encrypted_psu(a, c, exp, cryptoContext, keyPair, set_size);
    //the server sends this to the client and the client decrypts the result
    cryptoContext->Decrypt(keyPair.secretKey, psu_tt, &psu_t);
    psu = MultiplyMany(psu_t, cryptoContext, set_size);
    auto l_c_a = psu;

    //l_c_b=PSU(B, C) 
    //the server computes psu(b_rot, c) over the encrypted databases
    psu_tt = encrypted_psu(b_rot, c, exp, cryptoContext, keyPair, set_size);
    //the server sends this to the client and the client decrypts the result
    cryptoContext->Decrypt(keyPair.secretKey, psu_tt, &psu_t);
    psu = MultiplyMany(psu_t, cryptoContext, set_size);
    auto l_c_b = psu;

    //now the client computes l_c_a*l_c_b (over the plaintext)
    std::vector<int64_t> v1, v2;
    v1 = l_c_a->GetPackedValue();
    v2 = l_c_b->GetPackedValue();
    for (size_t i = 0; i < set_size; ++i) {
        v1[i] = v1[i]*v2[i];
    }
    l_c_a = cryptoContext->MakePackedPlaintext(v1);
    l_c = cryptoContext->Encrypt(keyPair.publicKey, l_c_a);
    //the client sends the list containing encryptions of 0's and/or 1's to the server
    //the server computes the product
    C = cryptoContext->EvalMult(C, l_c);
    //psu of 3 parties finished
    
    //***************Computing simple statistics***************
    //now we the server computes homomorphically some statistics: the average age 

    //we generate random sets, one for each party
    std::uniform_int_distribution<> dist(0, 60);
    std::vector<std::vector<int64_t>> ages(3);

    for (size_t i = 0; i < 3; ++i) {
        for (size_t j = 0; j < set_parties[i].size(); ++j) {
            ages[i].push_back(dist(gen));
        }
    }

    Plaintext a_age = get_simple_plaintext(ages[0], cryptoContext);
    Plaintext b_age = get_simple_plaintext(ages[1], cryptoContext);
    Plaintext c_age = get_simple_plaintext(ages[2], cryptoContext);

    auto A_age = cryptoContext->Encrypt(keyPair.publicKey, a_age);
    auto B_age = cryptoContext->Encrypt(keyPair.publicKey, b_age);
    auto C_age = cryptoContext->Encrypt(keyPair.publicKey, c_age);

    //now the server multiplies each ciphertext by its corresponding list
    B_age = cryptoContext->EvalMult(B_age, l_b);
    C_age = cryptoContext->EvalMult(C_age, l_c);

    //the server computes |A U B U C| homomorphically
    //we assume that party A sends the server a ciphertext, a_column, containig |A| encryptions of 1's 
    //and the rest 0's. Therefore we do not leak the cardinality of any party's database
    std::vector<int64_t> p(set_parties[0].size(), 1);
    Plaintext p_ = cryptoContext->MakePackedPlaintext(p);
    auto a_column = cryptoContext->Encrypt(keyPair.publicKey, p_);

    auto card = cryptoContext->EvalAdd(l_b, l_c);
    card = cryptoContext->EvalAdd(card, a_column);
    //card is sent to the client and the client decrypts the result
    cryptoContext->Decrypt(keyPair.secretKey, card, &p_);
    std::vector<int64_t> v_card;
    v_card = p_->GetPackedValue();
    long int cardinality = 0;
    for (size_t i = 0; i < set_size; ++i) cardinality += v_card[i];

    //the server computes the sum of the age over the ciphertexts
    auto SUM_age = A_age;
    SUM_age = cryptoContext->EvalAdd(SUM_age, B_age);
    SUM_age = cryptoContext->EvalAdd(SUM_age, C_age);
    //SUM_age is sent to the client and the client decrypts the result
    Plaintext sum_age;
    cryptoContext->Decrypt(keyPair.secretKey, SUM_age, &sum_age);
    std::vector<int64_t> v_age;
    v_age = sum_age->GetPackedValue();
    long int total_age_sum = 0;
    for (size_t i = 0; i < set_size; ++i) total_age_sum += v_age[i];

    std::cout << "The average age is " << total_age_sum / (double)cardinality << std::endl;
    std::cout << "Homomorphically computed |A U B U C| = " << cardinality << std::endl;

    std::set<int64_t> actual_union;
    for (size_t i = 0; i < n_parties; ++i) {
        std::set_union(actual_union.begin(), actual_union.end(),
            set_parties[i].begin(), set_parties[i].end(),
            std::inserter(actual_union, actual_union.begin()));
    }
    std::cout << "Real |A U B U C| = " << actual_union.size() << std::endl;

    //***************Compare the result***************
    cryptoContext->Decrypt(keyPair.secretKey, A, &A_);
    cryptoContext->Decrypt(keyPair.secretKey, B, &B_);
    cryptoContext->Decrypt(keyPair.secretKey, C, &C_);
    std::vector<std::vector<int64_t>> v_result(n_parties);
    v_result[0] = A_->GetPackedValue();
    v_result[1] = B_->GetPackedValue();
    v_result[2] = C_->GetPackedValue();
    for (size_t i = 0; i < n_parties; ++i) {
        for (size_t j = 0; j < set_parties[i].size(); ++j) {
            if (v_result[i][j] != 0) {
                if (actual_union.find(v_result[i][j]) == actual_union.end()) {
                    std::cout << "Something went wrong :(" << std::endl;
                }
                else {
                    actual_union.erase(v_result[i][j]);
                }
            }
        }
    }

    if (actual_union.size() == 0) {
        std::cout << "PSU performed correctly" << std::endl;
    }
    else {
        std::cout << "Something went wrong :(" << std::endl;
    }

    return 0;

}