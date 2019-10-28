/*
 * MIT License
 *
 * Copyright(c) 2019 Light's Hope (https://lightshope.org)
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this softwareand associated documentation files(the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and /or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions :
 *
 * The above copyright noticeand this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <botan/auto_rng.h>
#include <botan/x509_key.h>
#include <botan/ecdsa.h>
#include <botan/ec_group.h>
#include <botan/pubkey.h>
#include <botan/hex.h>
#include <botan/pkcs8.h>
#include <botan/ecdh.h>
#include <iostream>
#include <fstream>
#include <string>
#include <string_view>
#include <sstream>
#include <unordered_map>
#include <utility>

using namespace std::literals;

enum class Argument {
	JSON_FILE,
	PUB_KEY,
	SIGNATURE
};

struct Option {
	std::string_view cmd, help;
};

typedef std::unordered_map<Argument, std::string_view> ExtractedArgs;
ExtractedArgs extracted_params;

const std::unordered_map<Argument, Option> expected_params {
	{ Argument::JSON_FILE, {"-json",      "filename of the JSON document"          } },
	{ Argument::PUB_KEY,   {"-pubkey",    "the public key to verify the signature" } },
	{ Argument::SIGNATURE, {"-signature", "the expected file signature"            } }
};

ExtractedArgs extract_args(const char* argv[]);
std::string extract_file(const ExtractedArgs& args);
bool verify(const ExtractedArgs& args, const std::string& data);

int main(const int argc, const char* argv[]) try {
	if (argc < 2) {
		throw std::runtime_error("Missing arguments. Use -help for a full list.");
	}

	const auto args = extract_args(argv);
	const auto file = std::move(extract_file(args));
	auto ret = verify(args, std::move(file));

	std::cout << (ret? "Signature OK" : "Signature invalid");
	return ret? 0 : 1;
} catch (const std::exception& e) {
	std::cerr << e.what();
	return -1;
}

std::string extract_file(const ExtractedArgs& args) {
	std::string file_contents;
	std::stringstream doc;

	if (const auto & res = args.find(Argument::JSON_FILE);
		res != args.end() && !args.at(Argument::JSON_FILE).empty()) {
		// load from provided path
		std::ifstream file;
		file.open(std::string(args.at(Argument::JSON_FILE))); // :(

		if (!file) {
			throw std::runtime_error("Unable to open specified file");
		}

		doc << file.rdbuf();

		if (!file) {
			throw std::runtime_error("Encountered an error while reading file");
		}
	} else {
		// try to extract the file from cin
		for (std::string line; std::getline(std::cin, line);) {
			doc << line << (std::cin.eof() ? "" : "\n");
		}
	}

	file_contents = std::move(doc.str());

	if (file_contents.empty()) {
		throw std::runtime_error("No data to verify. Really?");
	}

	return file_contents;
}

bool verify(const ExtractedArgs& args, const std::string& data) {
	if (const auto & res = args.find(Argument::PUB_KEY);
		res == args.end() || args.at(Argument::PUB_KEY).empty()) {
		throw std::runtime_error("Public key appears to be missing or empty.");
	}

	if (const auto & res = args.find(Argument::SIGNATURE);
		res == args.end() || args.at(Argument::SIGNATURE).empty()) {
		throw std::runtime_error("Signature appears to be missing or empty.");
	}

	const auto pub_key = Botan::X509::load_key(args.at(Argument::PUB_KEY).data());
	Botan::PK_Verifier verifier(*pub_key, "EMSA1(SHA-256)");
	verifier.update(data);

	const auto signature = Botan::BigInt::encode(
		Botan::BigInt(std::string(args.at(Argument::SIGNATURE)))
	);

	return verifier.check_signature(signature);
}

void print_help() {
	std::cerr << "Available options:\n";

	for (const auto& [arg, option] : expected_params) {
		std::cerr << option.cmd << ", " << option.help << "\n";
	}
}

ExtractedArgs extract_args(const char* argv[]) {
	ExtractedArgs extracted;

	for (auto i = 0u;; ++i) {
		if (!argv[i]) {
			break;
		}

		if (argv[i] == "-help"sv) {
			std::cout << "HALP" << std::endl;
			print_help();
			exit(-2);
		}

		if (!argv[i + 1]) {
			break;
		}

		for (const auto& [arg, option] : expected_params) {
			if (argv[i] == option.cmd) {
				extracted[arg] = argv[++i];
			}
		}
	}

	return extracted;
}