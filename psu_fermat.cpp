#include <random>
#include "psu_v1.h"
#include "openfhe.h"

#include <chrono>
using namespace std;

using namespace lbcrypto;
using namespace std::chrono;


/// @brief This computes x^y (mod p) with the fast exponentiation algorithm
/// @param base base of the power
/// @param exp exponent of the power
/// @param cryptoContext crypto context of the used scheme
/// @param keyPair pair of keys 
/// @param N size of the sets
/// @return returns a ciphertext containing the result of x^y (mod p)
Ciphertext<DCRTPoly>  exponentiation(Ciphertext<DCRTPoly> base,
                        long int exp, CryptoContext<DCRTPoly> cryptoContext, KeyPair<DCRTPoly> keyPair, size_t N)
{
    
    std::vector<int64_t> vectorOfInts1;

    for (size_t i = 0; i < N*N; ++i) {
        vectorOfInts1.push_back(1);
    }

    Plaintext plaintext1 = cryptoContext->MakePackedPlaintext(vectorOfInts1);

    auto t = cryptoContext->Encrypt(keyPair.publicKey, plaintext1);

    int mult = 0;
    int squares = 0;

    while (exp > 0)
    {
        if (exp % 2 != 0) {
            t = cryptoContext->EvalMult(t, base);
            mult += 1;
        }

 
        base = cryptoContext->EvalMult(base, base);
        squares += 1;
        exp /= 2;
    }

    std::cout << "MULTS: " << mult << std::endl;
    std::cout << "SQUARES: " << squares << std::endl;

    return t;

}

/// @brief this generates the rotated plaintext of a set 
/// @param list vector containing the elements of the set
/// @param cryptoContext crypto context of the used scheme
/// @param N size of the sets
/// @return returns a plaintext containing N rotated copies of the set, one for each possible cyclic rotation of the set
Plaintext get_rotated_plaintext(std::vector<int64_t> list, CryptoContext<DCRTPoly> cryptoContext, size_t N){

    std::vector<int64_t> rotated_list;

    //cout << "N: "<< N << endl;
    
    for (size_t i = 0; i < N; ++i){
        //cout << "i: "<< i << endl;
        for (size_t j = i*N; j < (i+1)*N; ++j){
            rotated_list.push_back(list[(j-i)%N]);
            //cout << "j: "<< (j-i)%N << endl;
        }
    }
    
    Plaintext ptxt = cryptoContext->MakePackedPlaintext(rotated_list);
    
    return ptxt;

    return 0;
}

/// @brief this generates a plaintext containing N copies of the set
/// @param list vector containing the elements of the set
/// @param cryptoContext crypto context of the used scheme
/// @param N size of the sets
/// @return returns a plaintext containing N copies of the set
Plaintext get_non_rotated_plaintext(std::vector<int64_t> list, CryptoContext<DCRTPoly> cryptoContext, size_t N){

    std::vector<int64_t> rotated_list;
    
    for (size_t i = 0; i < N; ++i){
        for (size_t j = 0; j < N; ++j){
            rotated_list.push_back(list[j]);
        }
    }
    
    Plaintext ptxt = cryptoContext->MakePackedPlaintext(rotated_list);
    
    return ptxt;

    return 0;
}

/// remove N
Plaintext get_simple_plaintext(std::vector<int64_t> list, CryptoContext<DCRTPoly> cryptoContext, size_t N) {
    Plaintext ptxt = cryptoContext->MakePackedPlaintext(list);

    return ptxt;
}

/// *********change name to encrypted_psu
/// @brief This computes PSU(a, b)
/// @param set_a rotated plaintext of the first set to encrypt
/// @param set_b plaintext containing N copies of the second set
/// @param cryptoContext crypto context of the used scheme
/// @param keyPair pair of keys 
/// @param N size of the sets
/// @return returns a ciphertext containing encryption of 0s and/or 1s
Ciphertext<DCRTPoly> PSU(Ciphertext<DCRTPoly> set_a, Ciphertext<DCRTPoly> set_b, long int exp, CryptoContext<DCRTPoly> cryptoContext, KeyPair<DCRTPoly> keyPair, size_t N) {

    auto ciphertext_sub = cryptoContext->EvalSub(set_a, set_b);
    auto ciphertext_fermat = exponentiation(ciphertext_sub, exp, cryptoContext, keyPair, N);

    return ciphertext_fermat;
}

/// @brief This collapses the N*N list Dec(PSU(a, b)) into an N list
/// @param list decrypted output of PSU
/// @param cryptoContext crypto context of the used scheme
/// @param N size of the sets
/// @return returns a plaintext containing a list of size N with 0s and/or 1s
Plaintext MultiplyMany(Plaintext list, CryptoContext<DCRTPoly> cryptoContext, size_t N) {
    std::vector<int64_t> rotated_list;
    rotated_list = list->GetPackedValue();
    /*
    std::cout << "Decrypted result of PSU (size N*N):" << std::endl;
    for (size_t i = 0; i < N*N; ++i) std::cout << rotated_list[i] << ' ';
    std::cout << std::endl;
    */
    std::vector<int64_t> vec_psu(N, 1);
    for (size_t i = 0; i < N; ++i) {
        for (size_t j = i; j < N*N; j += N) {
            if (rotated_list[j] == 0) vec_psu[i] = 0;
        }
    }
    /*
    std::cout << "Result of MultiplyMany(PSU) (size N):" << std::endl;
    for (size_t i = 0; i < N; ++i) std::cout << vec_psu[i] << ' ';
    std::cout << std::endl;
    */
    Plaintext psu = cryptoContext->MakePackedPlaintext(vec_psu);

    return psu;
}

int main() {
    
    //PARAMETER GENERATION AND CONTEXT SETUP

    const size_t SET_SIZE = pow(2, 7);
    CCParams<CryptoContextBFVRNS> parameters;
    parameters.SetPlaintextModulus(65537);
    //parameters.SetPlaintextModulus(2147483647);
    parameters.SetMultiplicativeDepth(20); //log2(SET_SIZE)+log2(24)+1 multiplications
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

    // Generate the relinearization key
    cryptoContext->EvalMultKeysGen(keyPair.secretKey);
    //cryptoContext->EvalSumKeyGen(keyPair.secretKey, keyPair.publicKey);

    // Generate the rotation evaluation keys
    // left shift positive index, right shift negative index
    //int size = pow(2, 2);
    //cryptoContext->EvalRotateKeyGen(keyPair.secretKey, {-size, size});

    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> distrib(1, 1 << 16); //need to change 23 to 26 to allow 8 decimal digits
    //std::uniform_int_distribution<> distrib(1, 1 << 4); //need to change 23 to 26 to allow 8 decimal digits

    const size_t N_PARTIES = 3;

    //std::cout << "We will compute the PSU of " << N_PARTIES << " parties each with a set of " << SET_SIZE << " elements." << std::endl;

    // Generate one random set for each party
    std::vector<std::vector<int64_t>> parties(N_PARTIES);

    for (size_t i = 0; i < N_PARTIES; ++i) {
        for (size_t j = 0; j < SET_SIZE; ++j) {
            parties[i].push_back(distrib(gen));
        }
    }

    //Plaintext ptxt = get_rotated_plaintext(parties[0], cryptoContext, SET_SIZE);
    //std::cout << "Plaintext rotated: " << ptxt << std::endl;

    std::vector<int64_t> vectorOfInts1;
    for (size_t i = 0; i < SET_SIZE; ++i) {
        vectorOfInts1.push_back(1);
    }
    
    // First plaintext vector is encoded
    //std::vector<int64_t> vectorOfInts1 = {62537,62537,62537,62537};
    //Plaintext plaintext1               = cryptoContext->MakePackedPlaintext(vectorOfInts1);
    // Second plaintext vector is encoded
    //std::vector<int64_t> vectorOfInts2 = {62534,62534,62537,62532};
    //Plaintext plaintext2               = cryptoContext->MakePackedPlaintext(vectorOfInts2);

    //Plaintext plaintext1 = cryptoContext->MakePackedPlaintext(vectorOfInts1);
    //Plaintext plaintext2 = cryptoContext->MakePackedPlaintext(vectorOfInts2);

    Plaintext plaintext1 = cryptoContext->MakePackedPlaintext(parties.at(0));
    Plaintext plaintext2 = cryptoContext->MakePackedPlaintext(parties.at(1));

    // The encoded vectors are encrypted
    auto ciphertext1 = cryptoContext->Encrypt(keyPair.publicKey, plaintext1);
    auto ciphertext2 = cryptoContext->Encrypt(keyPair.publicKey, plaintext2);

    Plaintext plaintext_test = cryptoContext->MakePackedPlaintext(vectorOfInts1);
    auto ciphertext_test = cryptoContext->Encrypt(keyPair.publicKey, plaintext_test);

    // Sample Program: Step 4 - Evaluation
    auto ciphertextSub12     = cryptoContext->EvalSub(ciphertext1, ciphertext2);

    // Sample Program: Step 5 - Decryption

    Plaintext plaintextSubResult;
    cryptoContext->Decrypt(keyPair.secretKey, ciphertextSub12, &plaintextSubResult);

    //std::cout << "Plaintext #1: " << plaintext1 << std::endl;
    //std::cout << "Plaintext #2: " << plaintext2 << std::endl;

    long int exp = 65536;
 
    auto start = high_resolution_clock::now();
    auto ciphertextFermat = exponentiation(ciphertextSub12, exp, cryptoContext, keyPair, SET_SIZE);
    auto stop = high_resolution_clock::now();

    Plaintext plaintextFermatResult;
    cryptoContext->Decrypt(keyPair.secretKey, ciphertextFermat, &plaintextFermatResult);

    auto duration = duration_cast<seconds>(stop - start);
/*
    std::cout << "Fermat: " << plaintextFermatResult << std::endl;

    cout << "Time taken by Fermat: "
         << duration.count() << " seconds" << endl;

    
    for (size_t i = 0; i < 1; ++i) {
        ciphertextFermat = cryptoContext->EvalMult(ciphertextFermat, ciphertext_test);
    }

    Plaintext plaintext_test_mult;
    cryptoContext->Decrypt(keyPair.secretKey, ciphertextFermat, &plaintext_test_mult);
    std::cout << "Mult test: " <<plaintext_test_mult << std::endl;
*/
    //We do not need to care about how many multiplications we can do after this since
    //it will get decrypted and freshly encrypted by the decrypting party. In fact, we only
    //Care about the number of total multiplications that we can do in general between 
    //ciphertexts. 

    //To do: Implement generation of set A rotated and copy of set B not rotated (reuse Erik code)
    //To do: Implement MultiplyMany
    //To do: Implement Statistics
    //To do: Implement code for n > 2
    //To do: Add good documentation to the code

    //***************ERIK's TESTS**********************
    parties[0][1] = parties[1][3];
    /*
    std::cout << "First set before PSU:" << std::endl;
    for (size_t i = 0; i < SET_SIZE; ++i) std::cout << parties[0][i] << ' ';
    std::cout << std::endl;

    std::cout << "Second set before PSU:" << std::endl;
    for (size_t i = 0; i < SET_SIZE; ++i) std::cout << parties[1][i] << ' ';
    std::cout << std::endl;

    std::cout << "Third set before PSU:" << std::endl;
    for (size_t i = 0; i < SET_SIZE; ++i) std::cout << parties[2][i] << ' ';
    std::cout << std::endl;
    */
    Plaintext a_ = get_rotated_plaintext(parties[0], cryptoContext, SET_SIZE);

    Plaintext b_ = get_non_rotated_plaintext(parties[1], cryptoContext, SET_SIZE);

    auto a = cryptoContext->Encrypt(keyPair.publicKey, a_);
    /*
    Plaintext O;
    cryptoContext->Decrypt(keyPair.secretKey, a, &O);
    std::cout << O << std::endl;
    */
    auto b = cryptoContext->Encrypt(keyPair.publicKey, b_);
    Ciphertext<DCRTPoly> psu_tt;
    double u = 0;
    size_t n_iter = 1;
    for (size_t i = 0; i < n_iter; ++i) {
    start = high_resolution_clock::now();
    psu_tt = PSU(a, b, exp, cryptoContext, keyPair, SET_SIZE);
    stop = high_resolution_clock::now();
    duration = duration_cast<seconds>(stop - start);
    u += duration.count();
    }
    //Ciphertext<DCRTPoly> psu_tt = PSU(a, b, exp, cryptoContext, keyPair, SET_SIZE);
    std::cout << "Average time taken for a PSU of n = 2 and N = " << SET_SIZE << ": " << u/n_iter << " seconds" << std::endl;
    Plaintext psu_t;
    cryptoContext->Decrypt(keyPair.secretKey, psu_tt, &psu_t);
    Plaintext psu = MultiplyMany(psu_t, cryptoContext, SET_SIZE);
    auto d = cryptoContext->Encrypt(keyPair.publicKey, psu); //this is not necessary

    //std::cout << "Second set after PSU:" << std::endl;

    Plaintext B_ = get_simple_plaintext(parties[1], cryptoContext, SET_SIZE);
    auto B = cryptoContext->Encrypt(keyPair.publicKey, B_);

    auto c = cryptoContext->EvalMult(B, d); //this can be performed as B * psu
    /*****The idea is to add the plaintext modulus to wrap the negative numbers, it does not work
    std::vector<int64_t> v_int(SET_SIZE, 1);
    std::vector<int64_t> v_exp(SET_SIZE, exp);
    Plaintext ptxt1 = cryptoContext->MakePackedPlaintext(v_int);
    c = cryptoContext->EvalAdd(c, ptxt1);
    ptxt1 = cryptoContext->MakePackedPlaintext(v_exp);
    c = cryptoContext->EvalAdd(c, ptxt1);
     */
    /*
    Plaintext c_;
    cryptoContext->Decrypt(keyPair.secretKey, c, &c_);
    std::vector<int64_t> v = c_->GetPackedValue();

    for (size_t i = 0; i < SET_SIZE; ++i) std::cout << v[i] << ' ';
    std::cout << std::endl;
*/  Ciphertext<DCRTPoly> l_b, l_c; //REMOVE after computing the for
    u = 0;
    for (size_t j = 0; j < n_iter; ++j) {
    //std::cout << "Now we try the PSU of n=3 parties..." << std::endl;
    parties[2][0] = parties[0][1];
    parties[2][1] = parties[1][2];
    a_ = get_rotated_plaintext(parties[0], cryptoContext, SET_SIZE);
    b_ = get_non_rotated_plaintext(parties[1], cryptoContext, SET_SIZE);
    auto b__ = get_rotated_plaintext(parties[1], cryptoContext, SET_SIZE);
    Plaintext c_ = get_non_rotated_plaintext(parties[2], cryptoContext, SET_SIZE);

    a = cryptoContext->Encrypt(keyPair.publicKey, a_);
    b = cryptoContext->Encrypt(keyPair.publicKey, b_);
    auto b_rot = cryptoContext->Encrypt(keyPair.publicKey, b__);
    c = cryptoContext->Encrypt(keyPair.publicKey, c_);

    Plaintext A_ = get_simple_plaintext(parties[0], cryptoContext, SET_SIZE);
    auto A = cryptoContext->Encrypt(keyPair.publicKey, A_);

    B_ = get_simple_plaintext(parties[1], cryptoContext, SET_SIZE);
    B = cryptoContext->Encrypt(keyPair.publicKey, B_);

    Plaintext C_ = get_simple_plaintext(parties[2], cryptoContext, SET_SIZE);
    auto C = cryptoContext->Encrypt(keyPair.publicKey, C_);

    start = high_resolution_clock::now();

    //B*PSU(A, B)
    psu_tt = PSU(a, b, exp, cryptoContext, keyPair, SET_SIZE);
    cryptoContext->Decrypt(keyPair.secretKey, psu_tt, &psu_t);
    psu = MultiplyMany(psu_t, cryptoContext, SET_SIZE);
    d = cryptoContext->Encrypt(keyPair.publicKey, psu);
    //auto l_b = d; //list for set B
    l_b = d; // REMOVE after computing the for
    B = cryptoContext->EvalMult(B, d);

    //C*PSU(A, C)
    psu_tt = PSU(a, c, exp, cryptoContext, keyPair, SET_SIZE);
    cryptoContext->Decrypt(keyPair.secretKey, psu_tt, &psu_t);
    psu = MultiplyMany(psu_t, cryptoContext, SET_SIZE);
    d = cryptoContext->Encrypt(keyPair.publicKey, psu);
    auto l_c_ = d;
    C = cryptoContext->EvalMult(C, d);

    //C*PSU(B, C) IMPORTANT: B must be rotated!!
    psu_tt = PSU(b_rot, c, exp, cryptoContext, keyPair, SET_SIZE);
    cryptoContext->Decrypt(keyPair.secretKey, psu_tt, &psu_t);
    psu = MultiplyMany(psu_t, cryptoContext, SET_SIZE);
    d = cryptoContext->Encrypt(keyPair.publicKey, psu);
    C = cryptoContext->EvalMult(C, d);
    //auto l_c = cryptoContext->EvalMult(l_c_, d); //list for set C
    l_c = cryptoContext->EvalMult(l_c_, d); // REMOVE after for

    stop = high_resolution_clock::now();
    duration = duration_cast<seconds>(stop - start);
    u += duration.count();
    }
    std::cout << "Average time taken for a PSU of n = 3 and N = " << SET_SIZE << ": " << u/n_iter << " seconds" << std::endl;

    //Now we will compute some statistics
    std::uniform_int_distribution<int> dist(0, 60);
    std::vector<std::vector<int64_t>> ages(3);

    for (size_t i = 0; i < 3; ++i) {
        for (size_t j = 0; j < SET_SIZE; ++j) {
            ages[i].push_back(dist(gen));
        }
    }

    //we add some collisions
    ages[0][1] = ages[1][3];
    ages[2][0] = ages[0][1];
    ages[2][1] = ages[1][2];

    Plaintext a_age = get_simple_plaintext(ages[0], cryptoContext, SET_SIZE);
    Plaintext b_age = get_simple_plaintext(ages[1], cryptoContext, SET_SIZE);
    Plaintext c_age = get_simple_plaintext(ages[2], cryptoContext, SET_SIZE);

    auto A_age = cryptoContext->Encrypt(keyPair.publicKey, a_age);
    auto B_age = cryptoContext->Encrypt(keyPair.publicKey, b_age);
    auto C_age = cryptoContext->Encrypt(keyPair.publicKey, c_age);

    //now multiply each ciphertext by its corresponding list
    B_age = cryptoContext->EvalMult(B_age, l_b);
    C_age = cryptoContext->EvalMult(C_age, l_c);

    //we compute |A U B U C|
    auto card = cryptoContext->EvalAdd(l_b, l_c);
    std::vector<int64_t> p(SET_SIZE, 1);
    Plaintext p_ = cryptoContext->MakePackedPlaintext(p);
    card = cryptoContext->EvalAdd(card, p_);
    //send card to decrypting party

    //decrypting party computes
    cryptoContext->Decrypt(keyPair.secretKey, card, &p_);
    std::vector<int64_t> v_card;
    v_card = p_->GetPackedValue();
    long int cardinality = 0;
    for (size_t i = 0; i < SET_SIZE; ++i) cardinality += v_card[i];


    //we compute the sum of the age over the ciphertexts
    auto SUM_age = A_age;
    SUM_age = cryptoContext->EvalAdd(SUM_age, B_age);
    SUM_age = cryptoContext->EvalAdd(SUM_age, C_age);
    //send SUM_age to decrypting party

    //decrypting party computes
    Plaintext sum_age;
    cryptoContext->Decrypt(keyPair.secretKey, SUM_age, &sum_age);
    std::vector<int64_t> v_age;
    v_age = sum_age->GetPackedValue();
    long int total_age_sum = 0;
    for (size_t i = 0; i < SET_SIZE; ++i) total_age_sum += v_age[i];

    std::cout << "The average age is " << total_age_sum / (double)cardinality << std::endl;
    std::cout << "|A U B U C| = " << cardinality << std::endl;
/*
    for (size_t i = 0; i < 3; ++i) {
        for (size_t j = 0; j < SET_SIZE; ++j) {
            std::cout << parties[i][j] << ' ';
        }
        std::cout << std::endl;
    }
*/
/*
    for (size_t i = 0; i < 3; ++i) {
        for (size_t j = 0; j < SET_SIZE; ++j) {
            std::cout << ages[i][j] << ' ';
        }
        std::cout << std::endl;
    }
*/
/**************PRINT SETS AFTER PSU WITH n=3
    //A:
    cryptoContext->Decrypt(keyPair.secretKey, A, &A_);
    v = A_->GetPackedValue();
    std::cout << "First set after PSU, n=3:";
    for (size_t i = 0; i < SET_SIZE; ++i) std::cout << v[i] << ' ';
    std::cout << std::endl;

    //B:
    cryptoContext->Decrypt(keyPair.secretKey, B, &B_);
    v = B_->GetPackedValue();
    std::cout << "Second set after PSU, n=3:";
    for (size_t i = 0; i < SET_SIZE; ++i) std::cout << v[i] << ' ';
    std::cout << std::endl;

    //C:
    cryptoContext->Decrypt(keyPair.secretKey, C, &C_);
    //std::cout << C_ << std::endl;
    v = C_->GetPackedValue();
    std::cout << "Third set after PSU, n=3:";
    for (size_t i = 0; i < SET_SIZE; ++i) std::cout << v[i] << ' ';
    std::cout << std::endl;
*/
    return 0;

}