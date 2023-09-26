#include <stdint.h>
#include <vector>
#include <stdexcept>
#include <assert.h>

#include <napi.h>

struct lzss_params_t {
    size_t index_size;
    size_t length_size;
    size_t min_length;
    size_t initial_write_index;
};

lzss_params_t ZUN_LZSS_PARAMS = { 13, 4, 3, 1 };

void th06_decrypt_impl(uint8_t* buffer, const size_t length, uint8_t key, const size_t start) {
    for (size_t i = start; i < length; i++) {
        buffer[i] -= key;
        key += 7;
    }
}

void th_decrypt_impl(std::vector<uint8_t>& buffer, size_t block_size, uint8_t base, uint8_t add) {
    auto tbuf = buffer;
    size_t i, p = 0, tp1, tp2, hf, left = buffer.size();

    if ((left % block_size) < (block_size / 4))
        left -= left % block_size;

    if (left)
        left -= buffer.size() & 1;

    while (left) {
        if (left < block_size)
            block_size = left;

        tp1 = p + block_size - 1;
        tp2 = p + block_size - 2;
        hf = (block_size + (block_size & 0x1)) / 2;

        for (i = 0; i < hf; ++i, ++p) {
            buffer.at(tp1) = tbuf.at(p) ^ base;
            base += add;
            tp1 -= 2;
        }
        hf = block_size / 2;

        for (i = 0; i < hf; ++i, ++p) {
            buffer.at(tp2) = tbuf.at(p) ^ base;
            base += add;
            tp2 -= 2;
        }
        left -= block_size;
    }
}

std::vector<uint8_t> th_unlzss_impl(const uint8_t* in, size_t len, lzss_params_t& params = ZUN_LZSS_PARAMS) {
    struct bit_iter_t {
        // Huge optimization potential: using `in` ànd performing bit
        // operations on it's bytes directly. This doesn't matter for now
        std::vector<bool> data;
        size_t idx;

        size_t take(size_t n) {
            size_t ret = 0;
            for (size_t i = 0; i < n; i++) {
                if (idx >= data.size())
                    return ret;
                if (data[idx]) {
                    ret |= 1 << (n - i - 1);
                }
                idx++;
            }
            return ret;
        }

        bit_iter_t(const uint8_t* in, size_t len) : idx(0), data() {
            for (size_t i = 0; i < len; i++) {
                data.push_back(in[i] & 0b10000000);
                data.push_back(in[i] & 0b01000000);
                data.push_back(in[i] & 0b00100000);
                data.push_back(in[i] & 0b00010000);
                data.push_back(in[i] & 0b00001000);
                data.push_back(in[i] & 0b00000100);
                data.push_back(in[i] & 0b00000010);
                data.push_back(in[i] & 0b00000001);
            }
        }
    };
    
    bit_iter_t input_bits(in, len);

    std::vector<uint8_t> history(1 << params.index_size);
    size_t history_write_index = params.initial_write_index;

    std::vector<uint8_t> output_bytes;

    auto put_output_byte = [&](uint8_t byte) {
        output_bytes.push_back(byte);
        history[history_write_index] = byte;
        history_write_index += 1;
        history_write_index %= history.size();
    };

    for ( ; ; ) {
        bool control_bit = input_bits.take(1);
        if (control_bit) {
            uint8_t data_byte = static_cast<uint8_t>(input_bits.take(8));
            put_output_byte(data_byte);
        } else {
            size_t read_from = input_bits.take(params.index_size);
            if (!read_from)
                break;
            size_t read_count = input_bits.take(params.length_size) + params.min_length;

            for (size_t i = 0; i < read_count; i++) {
                put_output_byte(history[read_from]);
                read_from += 1;
                read_from %= history.size();
            }
        }
    }

    if (input_bits.data.size() != input_bits.idx) {
		throw std::runtime_error("The provided LZSS data is invalid or the LZSS parameters are wrong");
	}

    return output_bytes;
}

/// @brief Decrypts th06-compatible replay buffers
/// @param info Parameters of this function, `buffer`, `key` and `start`
/// @return `Null`, this function writes the output directly to the buffer
Napi::Value th06_decrypt(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();

    if (info.Length() > 3) {
        Napi::TypeError::New(env, "Too many arguments in function call!").ThrowAsJavaScriptException();
        return env.Null();
    } else if (info.Length() < 2) {
        Napi::TypeError::New(env, "Too few arguments in function call!").ThrowAsJavaScriptException();
        return env.Null();
    }

    if (!info[0].IsBuffer()) {
        Napi::TypeError::New(env, "First argument must be of buffer type!").ThrowAsJavaScriptException();
        return env.Null();
    }

    if (!info[1].IsNumber()) {
        Napi::TypeError::New(env, "Second argument must be of number type!").ThrowAsJavaScriptException();
        return env.Null();
    }

    if (info.Length() == 3 && !info[2].IsNumber()) {
        Napi::TypeError::New(env, "Third argument must be of number type!").ThrowAsJavaScriptException();
        return env.Null();
    }

    Napi::Buffer<uint8_t> buffer = info[0].As<Napi::Buffer<uint8_t>>();
    uint8_t key = info[1].As<Napi::Number>().Uint32Value();
    size_t start = (info.Length() == 3) ? info[2].As<Napi::Number>().Uint32Value() : 0;
    
    th06_decrypt_impl(buffer.Data(), buffer.Length(), key, start);
    
    return env.Null();
}

/// @brief Decrypts modern touhou replay buffers
/// @param info Parameters of this function, `buffer`, `block_size`, `base` and `add`
/// @return `Null`, this function writes the output directly to the buffer
Napi::Value th_decrypt(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();

    if (info.Length() > 4) {
        Napi::TypeError::New(env, "Too many arguments in function call!").ThrowAsJavaScriptException();
        return env.Null();
    } else if (info.Length() < 4) {
        Napi::TypeError::New(env, "Too few arguments in function call!").ThrowAsJavaScriptException();
        return env.Null();
    }

    if (!info[0].IsBuffer()) {
        Napi::TypeError::New(env, "First argument must be of buffer type!").ThrowAsJavaScriptException();
        return env.Null();
    }

    if (!info[1].IsNumber()) {
        Napi::TypeError::New(env, "Second argument must be of number type!").ThrowAsJavaScriptException();
        return env.Null();
    }

    if (!info[2].IsNumber()) {
        Napi::TypeError::New(env, "Third argument must be of number type!").ThrowAsJavaScriptException();
        return env.Null();
    }

    if (!info[3].IsNumber()) {
        Napi::TypeError::New(env, "Fourth argument must be of number type!").ThrowAsJavaScriptException();
        return env.Null();
    }

    try {
        Napi::Buffer<uint8_t> buffer = info[0].As<Napi::Buffer<uint8_t>>();
        size_t block_size = info[1].As<Napi::Number>().Uint32Value();
        uint8_t base = info[2].As<Napi::Number>().Uint32Value();
        uint8_t add = info[3].As<Napi::Number>().Uint32Value();

        std::vector<uint8_t> v_buffer(buffer.Data(), buffer.Data() + buffer.Length());

        try {
            th_decrypt_impl(v_buffer, block_size, base, add);
        } catch (const std::out_of_range& e) {
            Napi::RangeError::New(env, e.what()).ThrowAsJavaScriptException();
            return env.Null();
        }

        assert(buffer.Length() == v_buffer.size());
        memcpy(buffer.Data(), v_buffer.data(), buffer.Length());
    } catch (const std::bad_alloc& e) {
        Napi::Error::New(env, e.what()).ThrowAsJavaScriptException();
        return env.Null();
    }

    return env.Null();
}

/// @brief Uncompress replay data
/// @param info Parameters of this function, `buffer`
/// @return The buffer after being uncompressed
Napi::Value th_unlzss(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();

    if (info.Length() > 1) {
        Napi::TypeError::New(env, "Too many arguments in function call!").ThrowAsJavaScriptException();
        return env.Null();
    } else if (info.Length() < 1) {
        Napi::TypeError::New(env, "Too few arguments in function call!").ThrowAsJavaScriptException();
        return env.Null();
    }

    if (!info[0].IsBuffer()) {
        Napi::TypeError::New(env, "First argument must be of buffer type!").ThrowAsJavaScriptException();
        return env.Null();
    }

    try {
        Napi::Buffer<uint8_t> buffer = info[0].As<Napi::Buffer<uint8_t>>();

        try {
            auto result = th_unlzss_impl(buffer.Data(), buffer.Length());
            return Napi::Buffer<uint8_t>::Copy(env, result.data(), result.size());
        } catch (const std::runtime_error& e) {
            Napi::Error::New(env, e.what()).ThrowAsJavaScriptException();
            return env.Null();
        }
    } catch (const std::bad_alloc& e) {
        Napi::Error::New(env, e.what()).ThrowAsJavaScriptException();
        return env.Null();
    }

    return env.Null();
}

Napi::Object init(Napi::Env env, Napi::Object exports) {
    exports.Set(Napi::String::New(env, "decrypt06"), Napi::Function::New(env, th06_decrypt));
    exports.Set(Napi::String::New(env, "decrypt"), Napi::Function::New(env, th_decrypt));
    exports.Set(Napi::String::New(env, "unlzss"), Napi::Function::New(env, th_unlzss));
    return exports;
}

NODE_API_MODULE(NODE_GYP_MODULE_NAME, init);