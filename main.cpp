#include <string>
#include <vector>
#include <fstream>
#include <utility>
#include <memory>
#include <iostream>

#include <apsi/receiver.h>
#include <apsi/sender.h>
#include <apsi/network/stream_channel.h>

using namespace std;
using namespace apsi;

int main() {
    // Use 4 threads
    ThreadPoolMgr::SetThreadCount(4);

    // Full logging to console
    Log::SetLogLevel(Log::Level::all);
    Log::SetConsoleDisabled(false);

    // We use a StreamChannel object for networking here; this allows the user to
    // decide how to exactly communicate the data. This channel is backed in this
    // case by a std::stringstream, but some other C++ stream could be used as well.
    stringstream channel_stream;
    network::StreamChannel channel(channel_stream);

    // This example demonstrates the "advanced" API where you have to handle
    // networking yourself. The CLI provides an example of using the "simple" API.
    // These are described more in README.md.


    // We need to have APSI parameters first. Some example parameters
    // are available in the APSI repo in the parameters/ subdirectory.
    // Here we use some rather small parameters (in the local file params.json).
    ifstream params_fs("params.json", ios::in);
    string params_str, curr_line;
    while (getline(params_fs, curr_line)) {
        params_str.append(curr_line);
        params_str.append("\n");
    }
    PSIParams params = PSIParams::Load(params_str);
    
    // Create the Sender's database (we are setting up an unlabeled SenderDB here).
    // The SenderDB should typically live in a std::shared_ptr.
    shared_ptr<sender::SenderDB> sender_db = make_shared<sender::SenderDB>(params);

    // Let's insert a couple items
    vector<string> raw_sender_items{
        "Alice",
        "Bob",
        "Charlie",
        "Daniel",
        "Eve",
        "Fazila",
        "Gilbert" };

    // We need to convert the strings to Item objects
    vector<Item> sender_items(raw_sender_items.begin(), raw_sender_items.end());

    // Insert the items in the SenderDB 
    sender_db->insert_or_assign(sender_items);


    // Now suppose the Receiver wants to query for a couple items
    vector<string> raw_receiver_items{
        "Amir",
        "Charlie",
        "Danny",
        "Eve" };

    // We need to convert the strings to Item objects
    vector<Item> receiver_items(raw_receiver_items.begin(), raw_receiver_items.end());

    // The first step is to obtain OPRF values for these items, so we need to
    // create an oprf::OPRFReceiver object and use it to create an OPRF request
    oprf::OPRFReceiver oprf_receiver = receiver::Receiver::CreateOPRFReceiver(receiver_items);
    Request request = receiver::Receiver::CreateOPRFRequest(oprf_receiver);
    
    // Send the OPRF request on our communication channel (note the need to std::move it)
    channel.send(move(request));


    // The Sender must receive the OPRF request (need to convert it to OPRFRequest type)
    Request received_request = channel.receive_operation(sender_db->get_seal_context());
    OPRFRequest received_oprf_request = to_oprf_request(move(received_request));

    // Process the OPRF request and send a response back to the Receiver
    sender::Sender::RunOPRF(received_oprf_request, sender_db->get_oprf_key(), channel);


    // The Receiver can now get the OPRF response from the communication channel.
    // We need to extract the OPRF hashes from the response.
    Response response = channel.receive_response();
    OPRFResponse oprf_response = to_oprf_response(response);
    auto receiver_oprf_items = receiver::Receiver::ExtractHashes(
        oprf_response,
        oprf_receiver
    );

    // With the OPRF hashed Receiver's items, we are ready to create a PSI query.
    // First though, we need to create our Receiver object (assume here the Receiver
    // knows the PSI parameters). We need to keep the IndexTranslationTable object that
    // Receiver::create_query returns.
    receiver::Receiver receiver(params);
    pair<Request, receiver::IndexTranslationTable> query_data
        = receiver.create_query(receiver_oprf_items.first);
    receiver::IndexTranslationTable itt = query_data.second;
    request = move(query_data.first);

    // Now we are ready to send the PSI query request on our communication channel
    channel.send(move(request));


    // The Sender will then receive the PSI query request
    received_request = channel.receive_operation(sender_db->get_seal_context());
    QueryRequest received_query_request = to_query_request(received_request);

    // We need to extract the PSI query first
    sender::Query query(move(received_query_request), sender_db);

    // Process the PSI query request and send the response back to the Receiver
    sender::Sender::RunQuery(query, channel);


    // The Receiver then receives a QueryResponse object on the channel
    response = channel.receive_response();
    QueryResponse query_response = to_query_response(response);

    // The actual result data is communicated separately; the query response only
    // contains the number of ResultPart objects we expect to receive.
    uint32_t result_part_count = query_response->package_count;

    // Now loop to receive all of the ResultParts 
    vector<ResultPart> result_parts;
    while (result_part_count--) {
        ResultPart result_part = channel.receive_result(receiver.get_seal_context());
        result_parts.push_back(move(result_part));
    }

    // Finally process the result
    vector<receiver::MatchRecord> results
        = receiver.process_result(receiver_oprf_items.second, itt, result_parts);

    // The results vector indicates match information; the order matches the order
    // of the original input vector receiver_items
    for (size_t i = 0; i < raw_receiver_items.size(); i++) {
        cout << "Item " << raw_receiver_items[i] << ": ";
        cout << (results[i].found ? "FOUND" : "NOT FOUND") << endl;
    }


    return 0;
}
