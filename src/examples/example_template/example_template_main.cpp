// MIT License
//
// Copyright (c) 2019 Oleksandr Tkachenko
// Cryptography and Privacy Engineering Group (ENCRYPTO)
// TU Darmstadt, Germany
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.


//common c++ imports
#include <cmath>
#include <fstream>
#include <iostream>
#include <random>
#include <regex>

//includes for the dependencies
#include <fmt/format.h>
#include <boost/lexical_cast.hpp>
#include <boost/program_options.hpp>

//include from motion core
#include "base/party.h"
#include "common/example_template.h"
#include "communication/communication_layer.h"
#include "communication/tcp_transport.h"
//set namespace for parsing program options
namespace program_options = boost::program_options;
//declare function header for party arguments
bool CheckPartyArgumentSyntax(const std::string& party_argument);
//declare function header for parsing party arguments
std::pair<program_options::variables_map, bool> ParseProgramOptions(int ac, char* av[]);
//declare function header for creating parties
encrypto::motion::PartyPointer CreateParty(const program_options::variables_map& user_options);
//main function
int main(int ac, char* av[]) {
  auto [user_options, help_flag] = ParseProgramOptions(ac, av);
  // if help flag is set - print allowed command line arguments and exit
  if (help_flag) return EXIT_SUCCESS;
  //Create parties based on parameters
  encrypto::motion::PartyPointer party{CreateParty(user_options)};
  //Evaluate the protocol
  EvaluateProtocol(party);
  return EXIT_SUCCESS;
}
//Party Argument consists of ID, IP address, and port
const std::regex kPartyArgumentRegex(
    "(\\d+),(\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}),(\\d{1,5})");

//check if the party argument is in the correct syntax
bool CheckPartyArgumentSyntax(const std::string& party_argument) {
  // other party's id, IP address, and port
  return std::regex_match(party_argument, kPartyArgumentRegex);
}
//split the party argument into id, IP address, and port
std::tuple<std::size_t, std::string, std::uint16_t> ParsePartyArgument(
    const std::string& party_argument) {
  std::smatch match;
  std::regex_match(party_argument, match, kPartyArgumentRegex);
  auto id = boost::lexical_cast<std::size_t>(match[1]);
  auto host = match[2];
  auto port = boost::lexical_cast<std::uint16_t>(match[3]);
  return {id, host, port};
}

// <variables map, help flag>
std::pair<program_options::variables_map, bool> ParseProgramOptions(int ac, char* av[]) {
  using namespace std::string_view_literals;
  //Allows use of a configuration file
  constexpr std::string_view kConfigFileMessage =
      "configuration file, other arguments will overwrite the parameters read from the configuration file"sv;
  bool print, help;
  boost::program_options::options_description description("Allowed options");
  // clang-format off
  description.add_options()
      ("help,h", program_options::bool_switch(&help)->default_value(false),"produce help message")
      ("disable-logging,l","disable logging to file")
      ("print-configuration,p", program_options::bool_switch(&print)->default_value(false), "print configuration")
      ("configuration-file,f", program_options::value<std::string>(), kConfigFileMessage.data())
      ("my-id", program_options::value<std::size_t>(), "my party id")
      ("parties", program_options::value<std::vector<std::string>>()->multitoken(), "info (id,IP,port) for each party e.g., --parties 0,127.0.0.1,23000 1,127.0.0.1,23001");
  // clang-format on

  program_options::variables_map user_options;
  //uses the boost library to parse the command line arguments
  program_options::store(program_options::parse_command_line(ac, av, description), user_options);
  program_options::notify(user_options);

  // argument help or no arguments (at least a configuration file is expected)
  if (user_options["help"].as<bool>() || ac == 1) {
    std::cout << description << "\n";
    return std::make_pair<program_options::variables_map, bool>({}, true);
  }

  // read configuration file
  if (user_options.count("configuration-file")) {
    std::ifstream ifs(user_options["configuration-file"].as<std::string>().c_str());
    program_options::variables_map user_option_config_file;
    program_options::store(program_options::parse_config_file(ifs, description), user_options);
    program_options::notify(user_options);
  }

  // print parsed parameters
  if (user_options.count("my-id")) {
    if (print) std::cout << "My id " << user_options["my-id"].as<std::size_t>() << std::endl;
  } else
    throw std::runtime_error("My id is not set but required");

  if (user_options.count("parties")) {
    const std::vector<std::string> other_parties{
        user_options["parties"].as<std::vector<std::string>>()};
    std::string parties("Other parties: ");
    for (auto& p : other_parties) {
      if (CheckPartyArgumentSyntax(p)) {
        if (print) parties.append(" " + p);
      } else {
        throw std::runtime_error("Incorrect party argument syntax " + p);
      }
    }
    if (print) std::cout << parties << std::endl;
  } else
    throw std::runtime_error("Other parties' information is not set but required");

  return std::make_pair(user_options, help);
}
//Create the party by setting parameters and creating the pointer to the party object
//Sets the logging and communication layer
encrypto::motion::PartyPointer CreateParty(const program_options::variables_map& user_options) {
  const auto parties_string{user_options["parties"].as<const std::vector<std::string>>()};
  const auto number_of_parties{parties_string.size()};
  const auto my_id{user_options["my-id"].as<std::size_t>()};
  if (my_id >= number_of_parties) {
    throw std::runtime_error(fmt::format(
        "My id needs to be in the range [0, #parties - 1], current my id is {} and #parties is {}",
        my_id, number_of_parties));
  }

  encrypto::motion::communication::TcpPartiesConfiguration parties_configuration(number_of_parties);

  for (const auto& party_string : parties_string) {
    const auto [party_id, host, port] = ParsePartyArgument(party_string);
    if (party_id >= number_of_parties) {
      throw std::runtime_error(
          fmt::format("Party's id needs to be in the range [0, #parties - 1], current id "
                      "is {} and #parties is {}",
                      party_id, number_of_parties));
    }
    parties_configuration.at(party_id) = std::make_pair(host, port);
  }
  encrypto::motion::communication::TcpSetupHelper helper(my_id, parties_configuration);
  auto communication_layer = std::make_unique<encrypto::motion::communication::CommunicationLayer>(
      my_id, helper.SetupConnections());
  auto party = std::make_unique<encrypto::motion::Party>(std::move(communication_layer));
  auto configuration = party->GetConfiguration();
  // disable logging if the corresponding flag was set
  const auto logging{!user_options.count("disable-logging")};
  configuration->SetLoggingEnabled(logging);
  return party;
}
