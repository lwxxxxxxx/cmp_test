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
#include "libOTe/NChooseOne/Kkrt/KkrtNcoOtReceiver.h"
#include "libOTe/NChooseOne/Kkrt/KkrtNcoOtSender.h"
#include "libOTe/Vole/Silent/SilentVoleReceiver.h"
#include "libOTe/Vole/Silent/SilentVoleSender.h"
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
class cmp1{
private:
    BitVector bits;
    T *m;
    T *s;
    T *idx;
    T *a;
    T *c;
    T *w;
    BitVector r;
    T* t;
    
    Role role;
    AsioSocket chl;
    IknpOtExtSender *sender;
    IknpOtExtReceiver *recver;
    KkrtNcoOtSender *nsender;
    KkrtNcoOtReceiver *nrecver;
    SilentVoleReceiver<T> *volereceiver;
    SilentVoleSender<T> *volesender;
    PRNG prg;
    int n, ell;
    void initOT();
    void convert_offline(T p, int size);
    void convert_online(T p, int size, BitVector bits, T* output);
    void OLE(T* a1, T* c1);

    void permute(vector<T> choice);
    void VOLE();
    
    void oss_offline(vector<T> &pi, vector<T> &pi1);
    void oss_online(vector<T> &pi1, BitVector &res);
    void pre_sum();
    void get_index(BitVector &res);
public:
    cmp1(Role role, string ip, int n, int ell);
    void run(vector<block> data, BitVector &output, uint32_t ell, int numThreads = 1, bool random = true);
};

template<typename T>
cmp1<T>::cmp1(Role role, string ip, int n, int ell) {
    this->role = role;
    this->n = n;
    this->ell = ell;
    chl = coproto::asioConnect(ip, role == Role::Sender);
    prg.SetSeed(sysRandomSeed());
    initOT();
}

template<typename T>
void cmp1<T>::run(vector<block> data, BitVector &output, uint32_t ell, int numThreads, bool random) {
    if (random)
        prg.get(data.data(), data.size());
    int n = data.size();
    int numsize = n * ell;
    int sumsize = n * (ell + 2);
    int allsize = n * (ell + 2 + (ell<<1));

    int p = getmod(ell);
    bits.reserve(numsize);
    for (int i = 0; i < n; ++i) {
        bits.append((u8*)data[i].data(), ell);
    }
    vector<T> pi(allsize), pi1(allsize);

    m = new T[numsize]();
    s = new T[sumsize]();
    a = new T[allsize]();
    c = new T[allsize]();
    w = new T[allsize]();
    idx = new T[n * ell >> 1]();
    r.reset(numsize);
    t = new T[numsize];

    Timer timer;
    Timer::timeUnit offline_start, offline_end, online_start, online_end;

    cout << "=====offline start=====" << endl;
    u64 com_off_begin = chl.bytesReceived() + chl.bytesSent();
    offline_start = timer.setTimePoint("offline_start");

    convert_offline(p, numsize);
    oss_offline(pi, pi1);

    offline_end = timer.setTimePoint("offline_end");
    u64 com_off_end = chl.bytesReceived() + chl.bytesSent();
    
    cout << "=====offline end=====" << endl;
    sync_wait(sync(chl, role));
    //==========online===========
    cout << "=====oneline start=====" << endl;
    u64 com_begin = chl.bytesReceived() + chl.bytesSent();
    online_start = timer.setTimePoint("online_start");

    convert_online(p, numsize, bits, m);
    pre_sum();

    if (role == Role::Sender) {
        get_index(output);
    }
    oss_online(pi1, output);

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
void cmp1<T>::pre_sum() {
    int ell2 = ell + 2;
    if (role == Role::Sender) {
        for (int i = 0; i < n; ++i) {
            int tmpi = i * ell2;
            int pres = m[tmpi];
            s[tmpi] = 1 - pres;
            for (int j = 1; j < ell; ++j) {
                s[tmpi + j] = pres + 1 - m[tmpi+j];
                pres += m[tmpi+j];
            }
            s[tmpi + ell] = pres + 1;
            s[tmpi + ell + 1] = 1;
        }
    } else {
        for (int i = 0; i < n; ++i) {
            int tmpi = i * ell2;
            int pres = m[tmpi];
            s[tmpi] = 1 - pres;
            for (int j = 1; j < ell; ++j) {
                s[tmpi + j] = pres + 1 - m[tmpi+j];
                pres += m[tmpi+j];
            }
            s[tmpi + ell] = pres;
            s[tmpi + ell + 1] = 1;
        }
    }
}

template<typename T>
void cmp1<T>::get_index(BitVector &res) {
    for (int i = 0; i < n; ++i) {

    }
}

template<typename T>
void cmp1<T>::initOT() {
    cout << "initOT" << endl;
    bool maliciousSecure = false;
    uint64_t statSecParam = 40;
    uint64_t inputBitCount = log2(ell+2+(ell>>1));
    if (role == Role::Sender) {
        this->sender = new IknpOtExtSender();

        DefaultBaseOT base;
        BitVector bv(sender->baseOtCount());
        std::vector<block> base_msg(sender->baseOtCount());

        bv.randomize(prg);
        cp::sync_wait(base.receive(bv, base_msg, prg, chl));
        sender->setBaseOts(base_msg, bv);

        this->volereceiver = new SilentVoleReceiver<T>();
        volereceiver->mMultType = DefaultMultType;
        volereceiver->configure(n * (ell >> 1));

        nrecver = new KkrtNcoOtReceiver;
        nrecver->configure(maliciousSecure, statSecParam, inputBitCount);
        sync_wait(nrecver->genBaseOts(prg, chl));
    } else {
        this->recver = new IknpOtExtReceiver();
        DefaultBaseOT base;
        std::vector<std::array<block, 2>> base_msg(recver->baseOtCount());
        cp::sync_wait(base.send(base_msg, prg, chl));

        recver->setBaseOts(base_msg);

        this->volesender = new SilentVoleSender<T>();
        volesender->mMultType = DefaultMultType;
        volesender->configure(n * (ell >> 1));

        nsender = new KkrtNcoOtSender();
        nsender->configure(maliciousSecure, statSecParam, inputBitCount);

        sync_wait(nsender->genBaseOts(prg, chl));
    }
    cout << "end" << endl;
}


template<typename T>
void cmp1<T>::convert_offline(T p, int size) {
    r.randomize(prg);
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
void cmp1<T>::convert_online(T p, int size, BitVector bits, T* output) {
    BitVector w(size), tmp(size);

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
void cmp1<T>::OLE(T* a1, T* c1) {
    int ellp = log2(ell);
    int ell2 = ell+2;
    int numOTs = n * ell2 * ellp;
    int numsize = n * ell2;
    prg.get<T>(a1, numsize);
    if (role == Role::Sender) {
        T *r = new T[numOTs];
        prg.get<T>(r, numOTs);
        std::vector<std::array<block, 2>> messages(numOTs);
        T *pad = new T[numOTs * 2]();
        sender->send(messages, prg, chl);

        //#pragma omp parallel for
        for (int i = 0; i < numOTs; ++i) {
            int tmpi = i / ellp;
            pad[2*i] = *(T*)messages[i].data() ^ r[i];
            pad[2*i+1] = *(T*)messages[i].data() ^ (a1[tmpi] * (1 << (i%ellp)) + r[i]);
            c1[tmpi] -= r[i];
        }
        coproto::span<T> pat(pad, numOTs*2);
        sync_wait(chl.send(pat));
        delete[] pad;
        delete[] r;
    } else {
        BitVector choice;
        vector<block> message(numOTs);
        T *pad = new T[numOTs*2]();
        choice.reserve(numOTs);
        for (int i = 0; i < numsize; ++i) {
            choice.append(a1+i, ellp);
        }
        recver->receive(choice, message, prg, chl);
        coproto::span<T> pat(pad, numOTs*2);
        sync_wait(chl.recv(pat));

        //#pragma omp parallel for
        for (int i = 0; i < numOTs; ++i) {
            // int tmpi = i/ellp;
            c1[i/ellp] += *(T*)message[i].data() ^ pat[2*i+choice[i]];
        }
        delete[] pad;
    }
}

template<typename T>
void cmp1<T>::permute(vector<T> pi) {
    if (role == Role::Sender) {
        int sumsize = pi.size();
        Matrix<T> messages(sumsize, ell+2+(ell>>1));
        vector<block> message(sumsize);
        // one out of n

        sync_wait(nrecver->init(sumsize, prg, chl));

        //#pragma omp parallel for
        for(int i = 0; i < sumsize; ++i) {
            nrecver->encode(i, pi.data()+i, message.data()+i, sizeof(T));
        }

        sync_wait(nrecver->sendCorrection(chl, sumsize));
        sync_wait(chl.recv(messages));

        //#pragma omp parallel for
        for (int i = 0; i < sumsize; ++i) {
            w[i] = (c[i] + (*(T*)message[i].data() ^ messages(i, pi[i])));
        }

    } else {
        int inum = ell + 2 + (ell >> 1);
        int sumsize = n * inum;
        prg.get<T>(w, sumsize);
        Matrix<T> messages(sumsize, inum);
        
        sync_wait(nsender->init(sumsize, prg, chl));
        sync_wait(nsender->recvCorrection(chl, sumsize));

        block tmpm;
        //#pragma omp parallel for
        for (int i = 0; i < sumsize; ++i) {
            T tmpv = c[i] - w[i];
            for (int j = 0; j < inum; ++j) {
                nsender->encode(i, &j, &tmpm, sizeof(T));
                messages(i, j) = *(T*)tmpm.data() ^ tmpv;
            }
        }
        sync_wait(chl.send(messages));

    }
}


template<typename T>
void cmp1<T>::oss_offline(vector<T> &pi, vector<T> &pi1) {
    int ell2 = ell+2;
    int ellh = ell >> 1;
    int numVole = n * ellh;
    int single = ell2+ellh;
    T *a1 = new T[n*(ell2)]();
    T *c1 = new T[n*(ell2)]();
    if (role == Role::Sender) {
        pi.resize(n *single), pi1.resize(n*single);
        //#pragma omp parallel for
        for (int i = 0; i < n; ++i) {
            int tmpi = i * single;
            int tmpii = tmpi + single;
            std::random_device rd;
            std::mt19937 gen(rd());
            std::iota(pi.begin() + tmpi, pi.begin() + tmpii, 0);
            std::shuffle(pi.begin() + tmpi, pi.begin() + tmpii, gen);
            for (int j = 0; j < single; ++j) {
                pi1[tmpi+pi[tmpi+j]] = j;
            }
        }
    }
    OLE(a1, c1);
    if (role == Role::Sender) {
        AlignedUnVector<T> a2(numVole), c2(numVole);
        sync_wait(volereceiver->silentReceive(a2, c2, prg, chl));

        //#pragma omp parallel for
        for (int i = 0; i < n; ++i) {
            memcpy(a+i*single, a1, ell2);
            memcpy(c+i*single, c1, ell2);
            memcpy(a+i*single+ell2, a2.data(), ellh);
            memcpy(c+i*single+ell2, c2.data(), ellh);
        }
    } else {
        AlignedUnVector<T> c2(numVole);
        T a2 = prg.get<T>();

        sync_wait(volesender->silentSend(a2, c2, prg, chl));

        //#pragma omp parallel for
        for (int i = 0; i < n; ++i) {
            int tmpi = i * single;
            int tmpi1 = tmpi + ell2;
            memcpy(a+tmpi, a1, ell2);
            memcpy(c+tmpi, c1, ell2);
            memcpy(c+tmpi1, c2.data(), ellh);
            
            for (int j = 0; j < ellh; ++j) {
                a[tmpi1+j] = a2;
            }
        }
    }

    permute(pi);
}

template<typename T>
void cmp1<T>::oss_online(vector<T> &pi1, BitVector &res) {
    int ell2 = ell + 2;
    int ellh = ell >> 1;
    int single = ell2 + ellh;
    int sumsize = n * ell2, halfsize = n * ellh;
    T* d = new T[halfsize]();
    T* index = new T[halfsize];
    coproto::span<T> dp(d, halfsize), ip(index, halfsize);
    
    if (role == Role::Sender) {
        T* Y = new T[sumsize]();
        coproto::span<T> Yp(Y, sumsize);
        sync_wait(chl.recv(Yp));
        int tmpi, tmpj, tmpjj, tmphi;
        // //#pragma omp parallel for
        for (int i = 0; i < n; ++i) {
            tmpi = i * ell2;
            tmphi = i * ellh;
            for (int j = 0; j < ellh; ++j) {
                tmpj = tmpi + j;
                tmpjj = tmpi + idx[tmpj];
                index[tmphi + j] = pi1[tmpj];
                d[tmphi + j] = a[tmpjj] * (s[tmpjj] + Y[tmpj]) - w[tmpi + pi1[tmpj]];
            }
        }
        sync_wait(chl.send(dp));
        sync_wait(chl.send(ip));
    } else {
        for (int i = 0; i < sumsize; ++i) {
            s[i] += a[i];
        }
        coproto::span<T> sp(s, sumsize);
        sync_wait(chl.send(sp));

        
        sync_wait(chl.recv(dp));
        sync_wait(chl.recv(ip));

        int tmpi, tmpj, tmphi;
        // //#pragma omp parallel for
        for (int i = 0; i < n; ++i) {
            tmphi = i * ellh;
            tmpi = i * (single);
            for (int j = 0; j < ellh; ++j) {
                tmpj = tmphi + j;
                dp[tmpj] = dp[tmpj] - w[tmpi+ip[tmpj]];
                if (!dp[tmpj]) {
                    res[i] = 1;
                    break;
                }
            }
        }
    }
}