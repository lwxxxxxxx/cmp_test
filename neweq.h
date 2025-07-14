#pragma once

#include "libOTe/include/boost/variant/variant.hpp"
#include "cryptoTools/Common/Timer.h"
// #include "ots.h"
#include "utils.h"
#include "coproto/Common/macoro.h"
#include "coproto/Socket/AsioSocket.h"
#include "cryptoTools/Common/BitVector.h"
#include "cryptoTools/Common/block.h"
#include "cryptoTools/Crypto/PRNG.h"
#include "libOTe/Base/BaseOT.h"
#include "libOTe/TwoChooseOne/Iknp/IknpOtExtReceiver.h"
#include "libOTe/TwoChooseOne/Iknp/IknpOtExtSender.h"
#include "n1not.h"
#include <boost/type_traits/type_with_alignment.hpp>
#include <cstdint>
#include <macoro/sync_wait.h>
#include <vector>
#include <array>

using namespace std;
using namespace osuCrypto;
using namespace coproto;


template<typename T>
class eq1{
private:
    BitVector bits, share;
    uint8_t* epsilon;
    Role role;
    AsioSocket chl;
    IknpOtExtSender *sender;
    IknpOtExtReceiver *recver;
    PRNG prg;
    T *w, *tmp;
    void vose(BitVector &bits, uint8_t *delta, BitVector &output, int num, int size);
    void initOT(IknpOtExtSender *sender, IknpOtExtReceiver *recver);
public:
    eq1(Role role, string ip, IknpOtExtSender *sender, IknpOtExtReceiver *recver);
    eq1(Role role, AsioSocket &chl, IknpOtExtSender *sender, IknpOtExtReceiver *recver);
    void init(int n, uint32_t ell);
    void offline(int n, uint32_t ell);
    void online(int n, uint32_t ell, T* data, BitVector &output);
    void run(vector<T> data, BitVector &output, uint32_t ell, int numThreads = 1, bool random = true);
};

template<typename T>
class eq2{
    Role role;
    AsioSocket chl;
    IknpOtExtSender *sender;
    IknpOtExtReceiver *recver;
    PRNG prg;
    BitVector r;
    T* t;
    void initOT(IknpOtExtSender *sender, IknpOtExtReceiver *recver);
    void convert_offline(T p, int size);
    void convert_online(T p, int size, BitVector bits, T* output);
public:
    eq2(Role role, string ip, IknpOtExtSender *sender, IknpOtExtReceiver *recver);

    void run(vector<block> data, BitVector &output, uint32_t ell, int numThreads = 1, bool random = true);
    void online(int size, int len, T* lookupTable, T* delta, T* x, T* output);
};

template<typename T>
eq1<T>::eq1(Role role, string ip, IknpOtExtSender *sender, IknpOtExtReceiver *recver) {
    this->role = role;
    chl = coproto::asioConnect(ip, role == Role::Sender);
    prg.SetSeed(sysRandomSeed());
    initOT(sender, recver);
}

template<typename T>
eq1<T>::eq1(Role role, AsioSocket &chl, IknpOtExtSender *sender, IknpOtExtReceiver *recver) {
    this->role = role;
    this->chl = chl;
    prg.SetSeed(sysRandomSeed());
    initOT(sender, recver);
}

template<typename T>
void eq1<T>::initOT(IknpOtExtSender *sender_, IknpOtExtReceiver *recver_) {
    cout << "initOT" << endl;
    if (role == Role::Sender) {
        if (sender_ != NULL) {
            this->sender = sender_;
        } else {
            this->sender = new IknpOtExtSender();

            DefaultBaseOT base;
            BitVector bv(sender->baseOtCount());
            std::vector<block> base_msg(sender->baseOtCount());

            bv.randomize(prg);
            cp::sync_wait(base.receive(bv, base_msg, prg, chl));
            sender->setBaseOts(base_msg, bv);
        }
    } else {
        if (recver_) {
            this->recver = recver_;
        } else {
            this->recver = new IknpOtExtReceiver();
            DefaultBaseOT base;
            std::vector<std::array<block, 2>> base_msg(recver->baseOtCount());
            cp::sync_wait(base.send(base_msg, prg, chl));

            recver->setBaseOts(base_msg);
        }
    }
    cout << "end" << endl;
}

template<typename T>
void eq1<T>::offline(int n, uint32_t ell2) {
    if (role == Role::Sender) {
        prg.get(epsilon, n);
        // //#pragma omp parallel for
        for (int i = 0; i < n; ++i) {
            epsilon[i] %= ell2;
            bits[i*ell2 + epsilon[i]] = 1;
        }
    } 
    vose(bits, epsilon, share, n, ell2);
}

template<typename T>
void eq1<T>::online(int n, uint32_t ell2, T* data, BitVector &output) {
    coproto::span<T> ws(w, n), tmps(tmp, n);
    if (role == Role::Sender) {
        // //#pragma omp parallel for
        for (int i = 0; i < n; ++i) {
            w[i] = data[i] + epsilon[i];
        }
        sync_wait(chl.recv(tmps));
        sync_wait(chl.send(ws));
        // sync_wait(sync(chl, role));
    } else {
        // //#pragma omp parallel for
        for (int i = 0; i < n; ++i) {
            ws[i] = epsilon[i] - data[i];
        }
        sync_wait(chl.send(ws));
        sync_wait(chl.recv(tmps));
        // sync_wait(sync(chl, role));
    }
    
    // //#pragma omp parallel for
    for (int i = 0; i < n; ++i) {
        output[i] = share[i*ell2 + ((w[i] + tmp[i]) % ell2)];
    }
}

template<typename T>
void eq1<T>::init(int n, uint32_t ell2) {
    epsilon = new uint8_t[n]();
    w = new T[n]();
    tmp = new T[n]();
    int sumsize = n * ell2;
    bits.reset(sumsize);
    share.reset(sumsize);
}

template<typename T>
void eq1<T>::run(vector<T> data, BitVector &output, uint32_t ell, int numThreads, bool random) {
    if (random)
        prg.get(data.data(), data.size());
    int n = data.size();

    
    // vector<Share> s(ell*n), d(n), d2(n);
    // vector<bool> e(n);


    int p = getmod(ell);

    epsilon = new uint8_t[n]();
    
    int ell2 = 1 << ell;
    int sumsize = n * ell2;
    bits.reset(sumsize);
    share.reset(sumsize);
    // BitVector bits(sumsize);
    T *w = new T[n]();
    T *tmp = new T[n]();

    Timer timer;
    Timer::timeUnit offline_start, offline_end, online_start, online_end;
    Timer::timeUnit ot_start, ot_end;
    u64 off_com;
    if (role == Role::Sender) {
        //==========offline==========
        cout << "=====offline start=====" << endl;
        offline_start = timer.setTimePoint("offline_start");
        prg.get(epsilon, n);
        for (int i = 0; i < n; ++i) {
            epsilon[i] %= ell2;
            bits[i*ell2 + epsilon[i]] = 1;
        }
        vose(bits, epsilon, share, n, ell2);

        offline_end = timer.setTimePoint("offline_end");
        
        cout << "=====offline end=====" << endl;
        sync_wait(sync(chl, role));
        //==========online===========
        cout << "=====oneline start=====" << endl;
        online_start = timer.setTimePoint("online_start");
        coproto::span<T> ws(w, n), tmps(tmp, n);
        for (int i = 0; i < n; ++i) {
            w[i] = data[i] + epsilon[i];
        }
        sync_wait(chl.recv(tmps));
        sync_wait(chl.send(ws));
        // sync_wait(sync(chl, role));

        ////#pragma omp parallel for
        for (int i = 0; i < n; ++i) {
            output[i] = share[i*ell2 + ((w[i] + tmp[i]) % ell2)];
        }

        online_end = timer.setTimePoint("online_end");
        
    } else {
        offline_start = timer.setTimePoint("offline_start");
        
        vose(bits, epsilon, share, n, ell2);

        offline_end = timer.setTimePoint("offline_end");
        cout << "=====offline end=====" << endl;
        sync_wait(sync(chl, role));
        //==========online===========
        online_start = timer.setTimePoint("online_start");
        // uint64_t *w = new uint64_t[n]();
        // uint64_t *tmp = new uint64_t[n]();
        coproto::span<T> ws(w, n), tmps(tmp, n);
        for (int i = 0; i < n; ++i) {
            ws[i] = epsilon[i] - data[i];
        }
        sync_wait(chl.send(ws));
        sync_wait(chl.recv(tmps));
        // sync_wait(sync(chl, role));

        ////#pragma omp parallel for
        for (int i = 0; i < n; ++i) {
            output[i] = share[i*ell2 + ((w[i] + tmp[i]) % ell2)];
        }

        online_end = timer.setTimePoint("online_end");
    }
    auto offline_milli = std::chrono::duration_cast<std::chrono::milliseconds>(offline_end - offline_start).count();
    auto online_milli = std::chrono::duration_cast<std::chrono::milliseconds>(online_end - online_start).count();
    auto ot_milli = std::chrono::duration_cast<std::chrono::milliseconds>(ot_end - ot_start).count();
    u64 com = chl.bytesReceived() + chl.bytesSent();
    // for (int i = 0; i < n; ++i) {
    //     cout << e[i] << endl;
    // }
    // cout << "offline time: " << std::setw(6) << std::setfill(' ') << offline_milli << " ms   " << endl;
    cout << offline_milli << endl;
    cout << online_milli << endl;
    // cout << "ot      time: " << std::setw(6) << std::setfill(' ') << ot_milli << " ms   " << endl;
    cout << com - off_com << endl;
    cout << "===end===" << endl;
    coproto::sync_wait(chl.flush());
}

template<typename T>
void eq1<T>::vose(BitVector &bits, uint8_t *delta, BitVector &output, int nums, int size) {
    int simd_size = 16;
    uint64_t** seed = new uint64_t*[nums];
    for(int i = 0; i < nums; ++i) {
        seed[i] = new uint64_t[size]();
    }
    int simd_num = (size + 15)/simd_size;
    
    // TODO: 
    NCN1OT<uint64_t> ot(role, nums, size, sender, recver, chl);

    BitVector u;
    u.reset(nums*size);

    block* v_simd = new block[nums*simd_num];
    block* u_simd = new block[nums*simd_num];

    int sizebyte = size / 8;

    if (role == Role::Sender) {
        // start = clock_start();

        // hsio[0]->flush();
        ot.send(seed);
        // hsio[0]->flush();
        // timeused = time_from(start);
        // std::cout << party << "\tseed_gen\t" << timeused/1000 << "ms" << std::endl;

        // start = clock_start();
        //#pragma omp parallel for
        for (int i = 0; i < nums; ++i) {
            int tmp_i = i * size;
            int tmp, tmp_k0, tmp_jk;

            BitVector temp0(size), temp1;
            // bool* temp0 = new bool [size]();
            // bool* temp1 = new bool [size]();
            for (int j = 0; j < size; ++j) {
                block seed_one = toBlock(0, seed[i][j]);
                // printf("[%d][%d], seed = %lX\n",i,j,seed[i][j]);
                PRNG prng;
                prng.SetSeed(seed_one);
                prng.get<uint8_t>(temp0.data(), temp0.sizeBytes());
                for(int k = 0; k < simd_num; k++){
                    v_simd[i*simd_num + k] ^= *(temp0.blocks() + k);
                }
                
                
                temp1.copy(temp0, 0, size-j);
                temp1.append(temp0, j, size-j);
                // // printf("i=%d, &tmp=%d\n",i,&temp);
                // print(temp1,simd_size);
                for(int k = 0; k < simd_num; k++){
                    u_simd[i*simd_num + k] ^= *(temp1.blocks() + k);
                }
                
            }
            memcpy(output.data()+i*sizebyte, v_simd+i*simd_num, sizebyte);
            memcpy(u.data()+i*sizebyte, u_simd+i*simd_num, sizebyte);
        }
        // for (int i = 0; i < nums; ++i) {

        //     output.append((u8*)(v_simd+i*simd_num), size);
        //     u.append((u8*)(u_simd+i*simd_num), size);
        // }
        

        // timeused = time_from(start);
        // std::cout << party << "\tcal     \t" << timeused/1000 << "ms" << std::endl;

        // start = clock_start();

        ////#pragma omp parallel for
        for (int i = 0; i < bits.sizeBlocks(); ++i) {
            *(u.blocks() + i) ^= *(bits.blocks() + i);
        }

        // timeused = time_from(start);
        // std::cout << party << "\tcal2    \t" << timeused/1000 << "ms" << std::endl;

        // start = clock_start();

        // hsio[0]->flush();
        cout << u.sizeBytes() << endl;
        sync_wait(chl.send(u));
        sync_wait(chl.flush());
        // hsio[0]->send_data(u.data(), u.sizeBytes());
        // hsio[0]->send_data(uu, nums*size*lens*sizeof(T));
        // hsio[0]->flush();
        
        // timeused = time_from(start);
        // std::cout << party << "\tconv     \t" << timeused/1000 << "ms" << std::endl;

    } else {
        // start = clock_start();

        // hsio[0]->flush();
        ot.recv(seed, delta);
        // hsio[0]->flush();
        
        // timeused = time_from(start);
        // std::cout << party << "\tseed_gen\t" << timeused/1000 << "ms" << std::endl;

        // start = clock_start();
        //#pragma omp parallel for
        for (int i = 0; i < nums; ++i) {
            int tmp_i = i * size;
            int tmp, tmp_k0, tmp_jk;
            
            BitVector temp0(size), temp1;
            // T* temp0 = new T [size*lens]();
            // T* temp1 = new T [size*lens]();
            for (int j = 0; j < size; ++j) {
                block seed_one = toBlock(0, seed[i][j]);
                // printf("[%d][%d], seed = %lX\n",i,j,seed[i][j]);
                prg.SetSeed(seed_one);
                prg.get<uint8_t>(temp0.data(), temp0.sizeBytes());
                for(int k = 0; k < simd_num; k++){
                    v_simd[i*simd_num + k] ^= *(temp0.blocks() + k);
                }

                int tmp_jk = (j+size-delta[i])%size;
                
                temp1.copy(temp0, size-tmp_jk, tmp_jk);
                temp1.append(temp0, size-tmp_jk);
                // memcpy(temp1 + ((tmp_jk)), temp0, ((size-tmp_jk)) * sizeof(bool));
                // memcpy(temp1, temp0 + ((size-tmp_jk)), (tmp_jk) * sizeof(bool));
                // // printf("i=%d, &tmp=%d\n",i,&temp);
                // print(temp1,simd_size);
                for(int k = 0; k < simd_num; k++){
                    v_simd[i*simd_num + k] ^= *(temp1.blocks() + k);
                }
            }
            memcpy(output.data()+i*sizebyte, v_simd+i*simd_num, sizebyte);
        }
        // for (int i = 0; i < nums; ++i) {
        //     output.append((u8*)(v_simd+i*simd_num), size);
        // }
        
        // timeused = time_from(start);
        // std::cout << party << "\tcal     \t" << timeused/1000 << "ms" << std::endl;
        
        // start = clock_start();
        u.reset(nums*size);
        // hsio[0]->flush();
        // hsio[0]->recv_data(u.data(), u.sizeBytes());
        // hsio[0]->flush();
        cout << u.sizeBytes() << endl;
        sync_wait(chl.recv(u));
        sync_wait(chl.flush());
        
        // timeused = time_from(start);
        // std::cout << party << "\tconv    \t" << timeused/1000 << "ms" << std::endl;


        // start = clock_start();
        
        //#pragma omp parallel for
        for (int i = 0; i < nums; ++i) {
            int tmp_i = i*size;
            for (int j = 0; j < size; ++j) {
                output[tmp_i + j] = u[tmp_i + ((j + delta[i])%size)] - output[tmp_i + j];
            }
        }
        
        // timeused = time_from(start);
        // std::cout << party << "\tcal2    \t" << timeused/1000 << "ms" << std::endl;
    }
    // delete temp;
    free(u_simd);
    free(v_simd);
}

template<typename T>
eq2<T>::eq2(Role role, string ip, IknpOtExtSender *sender, IknpOtExtReceiver *recver) {
    this->role = role;
    chl = coproto::asioConnect(ip, role == Role::Sender);
    prg.SetSeed(sysRandomSeed());
    initOT(sender, recver);
}

template<typename T>
void eq2<T>::initOT(IknpOtExtSender *sender_, IknpOtExtReceiver *recver_) {
    cout << "initOT" << endl;
    if (role == Role::Sender) {
        if (sender_ != NULL) {
            this->sender = sender_;
        } else {
            this->sender = new IknpOtExtSender();

            DefaultBaseOT base;
            BitVector bv(sender->baseOtCount());
            std::vector<block> base_msg(sender->baseOtCount());

            bv.randomize(prg);
            cp::sync_wait(base.receive(bv, base_msg, prg, chl));
            sender->setBaseOts(base_msg, bv);
        }
    } else {
        if (recver_) {
            this->recver = recver_;
        } else {
            this->recver = new IknpOtExtReceiver();
            DefaultBaseOT base;
            std::vector<std::array<block, 2>> base_msg(recver->baseOtCount());
            cp::sync_wait(base.send(base_msg, prg, chl));

            recver->setBaseOts(base_msg);
        }
    }
    cout << "end" << endl;
}

template<typename T>
void eq2<T>::run(vector<block> data, BitVector &output, uint32_t ell, int numThreads, bool random) {
    if (random)
        prg.get(data.data(), data.size());
    int n = data.size();
    int size = n * ell;
    int p = getmod(ell);
    BitVector bits;
    bits.reserve(size);
    for (int i = 0; i < n; ++i) {
        bits.append((u8*)data.data(), ell);
    }
    

    t = new T[size]();
    r.reset(size);
    T *share = new T[size]();

    eq1<T> eq11(role, chl, sender, recver);
    eq11.init(n, ell);
    
    Timer timer;
    Timer::timeUnit offline_start, offline_end, online_start, online_end;

    cout << "=====offline start=====" << endl;
    u64 com_off_begin = chl.bytesReceived() + chl.bytesSent();
    offline_start = timer.setTimePoint("offline_start");

    convert_offline(p, size);
    eq11.offline(n, ell);

    offline_end = timer.setTimePoint("offline_end");
    u64 com_off_end = chl.bytesReceived() + chl.bytesSent();
    
    cout << "=====offline end=====" << endl;
    sync_wait(sync(chl, role));
    //==========online===========
    cout << "=====oneline start=====" << endl;
    u64 com_begin = chl.bytesReceived() + chl.bytesSent();
    online_start = timer.setTimePoint("online_start");

    convert_online(p, size, bits, share);
    cout << 2 << endl;
    eq11.online(n, ell, share, output);
    online_end = timer.setTimePoint("online_end");

    auto offline_milli = std::chrono::duration<double, std::milli>(offline_end - offline_start).count();
    auto online_milli = std::chrono::duration<double, std::milli>(online_end - online_start).count();
    u64 com = chl.bytesReceived() + chl.bytesSent();
    cout << "===" << endl;
    cout << "offline time: " << offline_milli << "ms" << endl;
    cout << "online  time: " << online_milli << "ms" << endl;
    cout << "total   comm: " << (com - com_begin) + (com_off_end - com_off_begin) << "bytes" << endl;
    cout << "online  comm: " << com - com_begin << "bytes" << endl;
}

template<typename T>
void eq2<T>::convert_offline(T p, int size) {
    prg.get(r.data(), r.sizeBytes());
    if (role == Role::Sender) {
        T *pad = new T[2*size];
        coproto::span<T> pat(pad, 2*size);
        prg.get(t, size);
        std::vector<std::array<block, 2>> data(size);
        sync_wait(sender->send(data, prg, chl));

        //#pragma omp parallel for
        for (int64_t i = 0; i < size; ++i) {
            pat[2*i] = *(T*)(data[i][0].data()) ^ ((t[i] - r[i]) % p);
            pat[2*i+1] = *(T*)(data[i][1].data()) ^ ((t[i] - 1 + r[i]) % p);
        }

        sync_wait(chl.send(pat));
        delete pad;
    } else {
        vector<block> data(size);
        sync_wait(recver->receive(r, data, prg, chl));
    
        T *pad = new T[2*size];
        coproto::span<T> pat(pad, 2 * size);
        sync_wait(chl.recv(pat));

        //#pragma omp parallel for
        for (int i = 0; i < size; ++i) {
            t[i] = *(T*)data[i].data() ^ pat[2*i+r[i]];
        }
    }
}

template<typename T>
void eq2<T>::convert_online(T p, int size, BitVector bits, T* output) {
    BitVector w(size), tmp(size);

    // //#pragma omp parallel for
    for (int i = 0; i < size; ++i) {
        w[i] = bits[i] ^ r[i];
    }

    if (role == Role::Sender) {
        sync_wait(chl.send(w));
        sync_wait(chl.recv(tmp));
        // //#pragma omp parallel for
        for (int i = 0; i < size; ++i) {
            w[i] = w[i] ^ tmp[i];
            output[i] = (w[i] + t[i] - 2*w[i]*t[i]);
        }
    } else {
        sync_wait(chl.recv(tmp));
        sync_wait(chl.send(w));
        // //#pragma omp parallel for
        for (int i = 0; i < size; ++i) {
            output[i] = (t[i] - 2*(w[i] ^ tmp[i]) * t[i]);
        }
    }
}



template<typename T>
void eq2<T>::online(int size, int len, T* lookupTable, T* delta, T* x, T* output) {
    T p = -1;
    prg.get(lookupTable, size * 256);
    prg.get(delta, size);
    prg.get(x, size);
    // BitVector w(size), tmp(size);
    Timer timer;
    auto online_start = timer.setTimePoint("online_start");
    T *tmp = new T[size];
    coproto::span<T> sx(x, size), temp(tmp, size);
    int offset = 0;
    int tablesize = 256*len;

    // //#pragma omp parallel for
    for (int i = 0; i < size; ++i) {
        x[i] = x[i] - delta[i];
    }

    if (role == Role::Sender) {
        sync_wait(chl.send(sx));
        sync_wait(chl.recv(temp));
    } else {
        sync_wait(chl.recv(temp));
        sync_wait(chl.send(sx));
    }
    
    for (int i = 0; i < size; ++i) {
        x[i] = x[i] + tmp[i];
        output[i] = lookupTable[offset + x[i]];
        offset += 256;
    }
    auto online_end = timer.setTimePoint("online_end");

    auto online_milli = std::chrono::duration<double, std::milli>(online_end - online_start).count();
    cout << "online time:" << online_milli << endl;
};
