#pragma once
#include <stdint.h>
#include <math.h>
#include "cryptoTools/Common/BitVector.h"
#include "coproto/Socket/AsioSocket.h"
#include <cryptoTools/Network/Channel.h>

enum class Role {
    Sender,
    Receiver
};

static inline uint32_t log2(uint32_t x) {
	uint32_t y;
	asm ( "\tbsr %1, %0\n"
		: "=r"(y)
		: "r" (x)
	);
	return x == (1 << y) ? y : y + 1;
}

int getmod(int num);

void shift(osuCrypto::BitVector &bits, int pos, int n);

coproto::task<> sync(coproto::Socket& chl, Role role);