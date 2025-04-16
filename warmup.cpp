#include "/halon/smtpd/HalonMTA.h"
#include <curl/curl.h>
#include <json/json.h>
#include <unistd.h>
#include <set>
#include <atomic>
#include <thread>
#include <syslog.h>
#include <list>
#include <mutex>

static std::atomic<bool> stop(false);
static std::atomic<bool> ready(false);
static std::thread websocketThread;
struct warmupItem
{
	int fields;
	std::vector<std::string> values;
	std::string id;
};
static std::mutex warmups_mutex;
static std::map<std::string, std::list<warmupItem>> warmups;

static void websocketWorker()
{
	std::set<std::string> uuid, uuid_last;
	while (!stop)
	{
		CURL *curl = curl_easy_init();
		if (!curl)
		{
			syslog(LOG_CRIT, "warmup: could not initialize libcurl");
			return;
		}

		curl_easy_setopt(curl, CURLOPT_URL, "ws://127.0.0.1:12345");
		curl_easy_setopt(curl, CURLOPT_CONNECT_ONLY, 2L);
		CURLcode res = curl_easy_perform(curl);
		if (res != CURLE_OK)
		{
			syslog(LOG_CRIT, "warmup: %s", curl_easy_strerror(res));
			curl_easy_cleanup(curl);
			sleep(1);
			continue;
		}

		// connected
		while (!stop)
		{
			size_t rlen;
			const struct curl_ws_frame *meta;
			char buffer[65535];
			CURLcode res = curl_ws_recv(curl, buffer, sizeof(buffer), &rlen, &meta);
			if (res == CURLE_OK)
			{
				buffer[rlen] = '\0';
				// printf("reading frame..\n");
				// printf("%s\n", buffer);

				Json::Value root;
				Json::Reader reader;
				reader.parse(buffer, root);

				if (root["action"].asString() == "CREATE")
				{
					auto id = root["policy"]["id"].asString();
					if (uuid_last.find(id) == uuid_last.end())
					{
						printf("-- create id %s\n", id.c_str());
						int fields = 0;
						std::vector<std::string> values;
						for (auto i = root["policy"]["fields"].begin(); i != root["policy"]["fields"].end(); ++i)
						{
							if (i->asString() == "TRANSPORTID")
							{
								fields |= HALONMTA_QUEUE_TRANSPORTID;
								values.push_back(root["policy"]["if"]["transportid"].isString() ? root["policy"]["if"]["transportid"].asString().c_str() : "");
							}
							if (i->asString() == "LOCALIP")
							{
								fields |= HALONMTA_QUEUE_LOCALIP;
								/* not adding to values */
							}
							if (i->asString() == "REMOTEIP")
							{
								fields |= HALONMTA_QUEUE_REMOTEIP;
								values.push_back(root["policy"]["if"]["remoteip"].isString() ? root["policy"]["if"]["remoteip"].asString().c_str() : "");
							}
							if (i->asString() == "REMOTEMX")
							{
								fields |= HALONMTA_QUEUE_REMOTEMX;
								values.push_back(root["policy"]["if"]["remotemx"].isString() ? root["policy"]["if"]["remotemx"].asString().c_str() : "");
							}
							if (i->asString() == "RECIPIENTDOMAIN")
							{
								fields |= HALONMTA_QUEUE_RECIPIENTDOMAIN;
								values.push_back(root["policy"]["if"]["recipientdomain"].isString() ? root["policy"]["if"]["recipientdomain"].asString().c_str() : "");
							}
							if (i->asString() == "JOBID")
							{
								fields |= HALONMTA_QUEUE_JOBID;
								values.push_back(root["policy"]["if"]["jobid"].isString() ? root["policy"]["if"]["jobid"].asString().c_str() : "");
							}
							if (i->asString() == "GROUPING")
							{
								fields |= HALONMTA_QUEUE_GROUPING;
								values.push_back(root["policy"]["if"]["grouping"].isString() ? root["policy"]["if"]["grouping"].asString().c_str() : "");
							}
							if (i->asString() == "TENANTID")
							{
								fields |= HALONMTA_QUEUE_TENANTID;
								values.push_back(root["policy"]["if"]["tenantid"].isString() ? root["policy"]["if"]["tenantid"].asString().c_str() : "");
							}
						}
						warmups_mutex.lock();
						warmups[root["policy"]["if"]["localip"].isString() ? root["policy"]["if"]["localip"].asString().c_str() : ""].push_back({fields,
																																				 values,
																																				 id});
						warmups_mutex.unlock();

						// XXX: handle all types..
						HalonMTA_queue_policy_add6(
							root["policy"]["id"].asString().c_str(),																			 // const chat* id
							fields,																												 // int fields,
							HALONMTA_POLICY_TYPE_WARMUP,																						 // int type,
							root["policy"]["if"]["transportid"].isString() ? root["policy"]["if"]["transportid"].asString().c_str() : 0,		 // const char* transportid,
							root["policy"]["if"]["localip"].isString() ? root["policy"]["if"]["localip"].asString().c_str() : 0,				 // const char* localip,
							root["policy"]["if"]["remoteip"].isString() ? root["policy"]["if"]["remoteip"].asString().c_str() : 0,				 // const char* remoteip,
							root["policy"]["if"]["remotemx"].isString() ? root["policy"]["if"]["remotemx"].asString().c_str() : 0,				 // const char* remotemx,
							root["policy"]["if"]["recipientdomain"].isString() ? root["policy"]["if"]["recipientdomain"].asString().c_str() : 0, // const char* recipientdomain,
							root["policy"]["if"]["jobid"].isString() ? root["policy"]["if"]["jobid"].asString().c_str() : 0,					 // const char* jobid,
							root["policy"]["if"]["grouping"].isString() ? root["policy"]["if"]["grouping"].asString().c_str() : 0,				 // const char* grouping,
							root["policy"]["if"]["tenantid"].isString() ? root["policy"]["if"]["tenantid"].asString().c_str() : 0,				 // const char*tenantidtransportid,
							root["policy"]["then"]["concurrency"].isNumeric() ? root["policy"]["then"]["concurrency"].asUInt64() : 0,			 // size_t concurrency,
							root["policy"]["then"]["tokens"].isNumeric() ? root["policy"]["then"]["tokens"].asUInt64() : 0,						 // size_t tokens,
							root["policy"]["then"]["interval"].isNumeric() ? root["policy"]["then"]["interval"].asDouble() : 0,					 // double interval,
							root["policy"]["then"]["connectinterval"].isNumeric() ? root["policy"]["then"]["connectinterval"].asDouble() : 0,	 // double connectinterval,
							root["policy"]["then"]["tag"].isString() ? root["policy"]["then"]["tag"].asString().c_str() : nullptr,				 // const char* tag,
							nullptr,																											 // const char* propv[],
							0,																													 // size_t propl,
							false,																												 // bool stop,
							true,																												 // bool cluster,
							0																													 // double ttl
						);
					}
					else
					{
						printf("-- updating existing policy!\n"); /// XXX?? update4 with stop?
						HalonMTA_queue_policy_update3(
							root["policy"]["id"].asString().c_str(),
							root["policy"]["then"]["concurrency"].isNumeric() ? root["policy"]["then"]["concurrency"].asUInt64() : 0,		  // size_t concurrency,
							root["policy"]["then"]["tokens"].isNumeric() ? root["policy"]["then"]["tokens"].asUInt64() : 0,					  // size_t tokens,
							root["policy"]["then"]["interval"].isNumeric() ? root["policy"]["then"]["interval"].asDouble() : 0,				  // double interval,
							root["policy"]["then"]["connectinterval"].isNumeric() ? root["policy"]["then"]["connectinterval"].asDouble() : 0, // double connectinterval,
							root["policy"]["then"]["tag"].isString() ? root["policy"]["then"]["tag"].asString().c_str() : nullptr,			  // const char* tag,
							nullptr,																										  // const char* propv[],
							0,																												  // size_t propl,
							true,																											  // bool cluster,
							0																												  // double ttl
						);
					}
					uuid.insert(root["policy"]["id"].asString());
				}
				if (root["action"].asString() == "UPDATE")
				{
					printf("-- update id %s\n", root["policy"]["id"].asString().c_str());
					// XXX: stop?
					HalonMTA_queue_policy_update3(
						root["policy"]["id"].asString().c_str(),
						root["policy"]["then"]["concurrency"].isNumeric() ? root["policy"]["then"]["concurrency"].asUInt64() : 0,		  // size_t concurrency,
						root["policy"]["then"]["tokens"].isNumeric() ? root["policy"]["then"]["tokens"].asUInt64() : 0,					  // size_t tokens,
						root["policy"]["then"]["interval"].isNumeric() ? root["policy"]["then"]["interval"].asDouble() : 0,				  // double interval,
						root["policy"]["then"]["connectinterval"].isNumeric() ? root["policy"]["then"]["connectinterval"].asDouble() : 0, // double connectinterval,
						root["policy"]["then"]["tag"].isString() ? root["policy"]["then"]["tag"].asString().c_str() : nullptr,			  // const char* tag,
						nullptr,																										  // const char* propv[],
						0,																												  // size_t propl,
						true,																											  // bool cluster,
						0																												  // double ttl
					);
				}
				if (root["action"].asString() == "DELETE")
				{
					auto id = root["policy"]["id"].asString();
					printf("-- delete id %s\n", id.c_str());
					HalonMTA_queue_policy_delete(id.c_str());
					uuid.erase(id);
					warmups_mutex.lock();
					for (auto i = warmups.begin(); i != warmups.end(); ++i)
					{
						for (auto x = i->second.begin(); x != i->second.end(); ++x)
						{
							if (x->id == id)
							{
								i->second.erase(x);
								goto loopend;
							}
						}
					}
				loopend:
					/* */;
					warmups_mutex.unlock();
				}
				if (root["action"].asString() == "SYNCED")
				{
					for (const auto &ul : uuid_last)
					{
						if (uuid.find(ul) == uuid.end())
						{
							printf("remove old policy %s\n", ul.c_str());
							HalonMTA_queue_policy_delete(ul.c_str());

							warmups_mutex.lock();
							for (auto i = warmups.begin(); i != warmups.end(); ++i)
							{
								for (auto x = i->second.begin(); x != i->second.end(); ++x)
								{
									if (x->id == ul)
									{
										i->second.erase(x);
										goto loopend2;
									}
								}
							}
						loopend2:
							/* */;
							warmups_mutex.unlock();
						}
					}
					ready = true;
					printf("ready!\n");
				}
			}
			else if (res == CURLE_AGAIN)
			{
				usleep(100000); // 100ms
				continue;
			}
			else
			{
				syslog(LOG_CRIT, "warmup: %s", curl_easy_strerror(res));
				break;
			}
		}

		// saving old rules...
		printf("making a copy of uuid_last\n");
		uuid_last = uuid;
		uuid.clear();

		// closing...
		size_t sent;
		(void)curl_ws_send(curl, "", 0, &sent, 0, CURLWS_CLOSE);
		curl_easy_cleanup(curl);
	}
}

HALON_EXPORT
int Halon_version()
{
	return HALONMTA_PLUGIN_VERSION;
}

HALON_EXPORT
bool Halon_init(HalonInitContext *hic)
{
	websocketThread = std::thread([]
								  { websocketWorker(); });
	while (!ready)
		usleep(100000);
	return true;
}

HALON_EXPORT
bool Halon_queue_preadd(HalonQueueContext *hqc)
{
	char **localips;
	size_t localips_count;
	HalonMTA_queue_getinfo(hqc, HALONMTA_INFO_LOCALIPS, nullptr, 0, &localips, &localips_count);

	bool modified = false;
	HalonQueueMessage *hqm = nullptr;
	std::vector<std::string> localips_touse;

	std::map<size_t, std::string> value_cache;

	warmups_mutex.lock();
	for (size_t i = 0; i < localips_count; ++i)
	{
		auto w = warmups.find(localips[i]);
		if (w == warmups.end())
		{
			localips_touse.push_back(localips[i]);
			continue;
		}

		// if matching.. add... or set modified = true
		bool match = false;
		for (const auto &condition : w->second)
		{
			std::vector<std::string> compare;
			for (const auto &p : (std::vector<std::pair<size_t, size_t>>){
					 {HALONMTA_QUEUE_TRANSPORTID, HALONMTA_MESSAGE_TRANSACTIONID},
					 {HALONMTA_QUEUE_REMOTEIP, HALONMTA_MESSAGE_REMOTEIP},
					 {HALONMTA_QUEUE_REMOTEMX, HALONMTA_MESSAGE_REMOTEMX},
					 {HALONMTA_QUEUE_RECIPIENTDOMAIN, HALONMTA_MESSAGE_RECIPIENTDOMAIN},
					 {HALONMTA_QUEUE_JOBID, HALONMTA_MESSAGE_JOBID},
					 {HALONMTA_QUEUE_GROUPING, HALONMTA_MESSAGE_GROUPING},
					 {HALONMTA_QUEUE_TENANTID, HALONMTA_MESSAGE_TENANTID},
				 })
			{
				if (condition.fields & p.first)
				{
					if (value_cache.find(p.first) == value_cache.end())
					{
						if (!hqm)
							HalonMTA_queue_getinfo(hqc, HALONMTA_INFO_MESSAGE, nullptr, 0, &hqm, nullptr);
						size_t vl;
						const char *v;
						HalonMTA_message_getinfo(hqm, p.second, nullptr, 0, &v, &vl);
						value_cache[p.first] = std ::string(v, vl);
						printf("fetching value..\n");
					}
					compare.push_back(value_cache[p.first]);
				}
			}
			printf("check policy %s %zu vs %zu\n", condition.id.c_str(), condition.values.size(), compare.size());
			if (condition.values == compare)
			{
				match = true;
				break;
			}
		}

		if (!match)
		{
			printf("does not match any condition\n");
			modified = true;
		}
		else
		{
			printf("match a condition\n");
			localips_touse.push_back(localips[i]);
		}

		printf("ip... %s\n", localips[i]);
	}
	warmups_mutex.unlock();

	if (modified)
	{
		const char **localips2 = new const char *[localips_touse.size()];
		for (size_t i = 0; i < localips_touse.size(); ++i)
			localips2[i] = localips_touse[i].c_str();
		HalonMTA_queue_setinfo(hqc, HALONMTA_INFO_LOCALIPS, localips2, localips_touse.size());
		delete[] localips2;
	}

	return true;
}

HALON_EXPORT
void Halon_cleanup()
{
	stop = true;
	websocketThread.join();
}
