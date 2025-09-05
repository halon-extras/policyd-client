#include <HalonMTA.h>
#include <curl/curl.h>
#include <json/json.h>
#include <unistd.h>
#include <set>
#include <atomic>
#include <thread>
#include <syslog.h>
#include <list>
#include <mutex>
#include <cstring>

static std::atomic<bool> stop(false);
static std::atomic<bool> ready(false);
static std::atomic<bool> error(false);
static std::thread websocketThread;

enum UUIDType
{
	SUSPEND,
	POLICY,
};

struct warmupItem
{
	int fields;
	std::vector<std::string> values;
	std::string id;
	UUIDType type;
};

static std::mutex warmups_mutex;
static std::map<std::string, std::list<warmupItem>> warmups;

static struct
{
	std::string address;
} Config;

struct UUID
{
	UUIDType type;
	std::string id;
};

struct UUIDCompare
{
	bool operator()(const UUID& a, const UUID& b) const
	{
		if (a.type != b.type)
			return a.type < b.type;
		return a.id < b.id;
	}
};

static void cleanupWarmup(UUIDType type, const std::string& id)
{
	std::lock_guard<std::mutex> lck(warmups_mutex);
	for (auto i = warmups.begin(); i != warmups.end(); ++i)
	{
		for (auto x = i->second.begin(); x != i->second.end(); ++x)
		{
			if (x->type == type && x->id == id)
			{
				i->second.erase(x);
				if (i->second.empty())
					warmups.erase(i);
				return;
			}
		}
	}
}

static void websocketWorker()
{
	std::set<UUID, UUIDCompare> uuid, uuid_last;
	while (!stop)
	{
		CURL* curl = curl_easy_init();
		if (!curl)
		{
			syslog(LOG_CRIT, "policyd-client: could not initialize libcurl");
			return;
		}

		curl_easy_setopt(curl, CURLOPT_URL, Config.address.c_str());
		curl_easy_setopt(curl, CURLOPT_CONNECT_ONLY, 2L);
		CURLcode res = curl_easy_perform(curl);
		if (res != CURLE_OK)
		{
			syslog(LOG_CRIT, "policyd-client: %s", curl_easy_strerror(res));
			curl_easy_cleanup(curl);
			sleep(1);
			continue;
		}
		syslog(LOG_CRIT, "connected");
		error = false;

		// connected
		while (!stop)
		{
			size_t rlen;
			const struct curl_ws_frame* meta;
			char buffer[65535];
			res = curl_ws_recv(curl, buffer, sizeof(buffer), &rlen, &meta);
			if (res == CURLE_OK)
			{
				buffer[rlen] = '\0';

				Json::Value root;
				Json::Reader reader;
				reader.parse(buffer, root);

				if (root["action"].asString() == "VERSION")
				{
					if (root["version"].asUInt64() != 1)
					{
						syslog(LOG_CRIT, "policyd-client: Unsupported version of policyd");
						error = true;
						return;
					}
				}
				if (root["action"].asString() == "CREATE")
				{
					if (root["policy"])
					{
						auto id = root["policy"]["id"].asString();

						std::vector<const char*> properties;
						if (root["policy"]["then"]["properties"])
						{
							for (auto i = root["policy"]["then"]["properties"].begin(); i != root["policy"]["then"]["properties"].end(); ++i)
							{
								properties.push_back(strdup(i.key().asCString()));
								properties.push_back(strdup(i->asCString()));
							}
						}

						if (uuid_last.find({ UUIDType::POLICY, id }) == uuid_last.end())
						{
							int type = HALONMTA_POLICY_TYPE_DYNAMIC;
							if (root["policy"]["type"].asString() == "WARMUP")
								type = HALONMTA_POLICY_TYPE_WARMUP;
							if (root["policy"]["type"].asString() == "BACKOFF")
								type = HALONMTA_POLICY_TYPE_BACKOFF;

							int ratealgorithm = HALONMTA_RATE_ALGORITHM_DEFAULT;
							if (root["policy"]["then"]["rate"]["algorithm"].asString() == "FIXEDWINDOW")
								ratealgorithm = HALONMTA_RATE_ALGORITHM_FIXEDWINDOW;
							if (root["policy"]["then"]["rate"]["algorithm"].asString() == "TOKENBUCKET")
								ratealgorithm = HALONMTA_RATE_ALGORITHM_TOKENBUCKET;

							int fields = 0;
							std::vector<std::string> values;
							for (auto i = root["policy"]["fields"].begin(); i != root["policy"]["fields"].end(); ++i)
							{
								if (i->asString() == "TRANSPORTID")
								{
									fields |= HALONMTA_QUEUE_TRANSPORTID;
									values.push_back(root["policy"]["if"]["transportid"].isString() ? root["policy"]["if"]["transportid"].asString() : "");
								}
								if (i->asString() == "LOCALIP")
								{
									fields |= HALONMTA_QUEUE_LOCALIP;
									/* not adding to values */
								}
								if (i->asString() == "REMOTEIP")
								{
									fields |= HALONMTA_QUEUE_REMOTEIP;
									values.push_back(root["policy"]["if"]["remoteip"].isString() ? root["policy"]["if"]["remoteip"].asString() : "");
								}
								if (i->asString() == "REMOTEMX")
								{
									fields |= HALONMTA_QUEUE_REMOTEMX;
									values.push_back(root["policy"]["if"]["remotemx"].isString() ? root["policy"]["if"]["remotemx"].asString() : "");
								}
								if (i->asString() == "RECIPIENTDOMAIN")
								{
									fields |= HALONMTA_QUEUE_RECIPIENTDOMAIN;
									values.push_back(root["policy"]["if"]["recipientdomain"].isString() ? root["policy"]["if"]["recipientdomain"].asString() : "");
								}
								if (i->asString() == "JOBID")
								{
									fields |= HALONMTA_QUEUE_JOBID;
									values.push_back(root["policy"]["if"]["jobid"].isString() ? root["policy"]["if"]["jobid"].asString() : "");
								}
								if (i->asString() == "GROUPING")
								{
									fields |= HALONMTA_QUEUE_GROUPING;
									values.push_back(root["policy"]["if"]["grouping"].isString() ? root["policy"]["if"]["grouping"].asString() : "");
								}
								if (i->asString() == "TENANTID")
								{
									fields |= HALONMTA_QUEUE_TENANTID;
									values.push_back(root["policy"]["if"]["tenantid"].isString() ? root["policy"]["if"]["tenantid"].asString() : "");
								}
							}

							if (type == HALONMTA_POLICY_TYPE_WARMUP)
							{
								if (root["policy"]["if"]["localip"].isString())
								{
									warmups_mutex.lock();
									warmups[root["policy"]["if"]["localip"].asString()]
										.push_back({ fields,
													 values,
													 id,
													 UUIDType::POLICY });
									warmups_mutex.unlock();
								}
								else
								{
									syslog(LOG_CRIT, "policy of typ warmup was missing localip");
								}
							}

							auto _id = HalonMTA_queue_policy_add6(
								root["policy"]["id"].asString().c_str(),																			 // const chat* id
								fields,																												 // int fields,
								type,																												 // int type,
								root["policy"]["if"]["transportid"].isString() ? root["policy"]["if"]["transportid"].asString().c_str() : 0,		 // const char* transportid,
								root["policy"]["if"]["localip"].isString() ? root["policy"]["if"]["localip"].asString().c_str() : 0,				 // const char* localip,
								root["policy"]["if"]["remoteip"].isString() ? root["policy"]["if"]["remoteip"].asString().c_str() : 0,				 // const char* remoteip,
								root["policy"]["if"]["remotemx"].isString() ? root["policy"]["if"]["remotemx"].asString().c_str() : 0,				 // const char* remotemx,
								root["policy"]["if"]["recipientdomain"].isString() ? root["policy"]["if"]["recipientdomain"].asString().c_str() : 0, // const char* recipientdomain,
								root["policy"]["if"]["jobid"].isString() ? root["policy"]["if"]["jobid"].asString().c_str() : 0,					 // const char* jobid,
								root["policy"]["if"]["grouping"].isString() ? root["policy"]["if"]["grouping"].asString().c_str() : 0,				 // const char* grouping,
								root["policy"]["if"]["tenantid"].isString() ? root["policy"]["if"]["tenantid"].asString().c_str() : 0,				 // const char*tenantidtransportid,
								root["policy"]["then"]["concurrency"].isNumeric() ? root["policy"]["then"]["concurrency"].asUInt64() : 0,			 // size_t concurrency,
								root["policy"]["then"]["rate"]["count"].isNumeric() ? root["policy"]["then"]["rate"]["count"].asUInt64() : 0,		 // size_t tokens,
								root["policy"]["then"]["rate"]["interval"].isNumeric() ? root["policy"]["then"]["rate"]["interval"].asDouble() : 0,	 // double interval,
								ratealgorithm,																										 // int ratealgorithm
								root["policy"]["then"]["connectinterval"].isNumeric() ? root["policy"]["then"]["connectinterval"].asDouble() : 0,	 // double connectinterval,
								root["policy"]["then"]["tag"].isString() ? root["policy"]["then"]["tag"].asString().c_str() : nullptr,				 // const char* tag,
								&properties[0],																										 // const char* propv[],
								properties.size(),																									 // size_t propl,
								root["policy"]["then"]["stop"].isBool() ? root["policy"]["then"]["stop"].asBool() : false,							 // bool stop,
								root["policy"]["then"]["cluster"].isBool() ? root["policy"]["then"]["cluster"].asBool() : true,						 // bool cluster,
								root["policy"]["ttl"].isNumeric() ? root["policy"]["ttl"].asDouble() : 0											 // double ttl
							);
							error = _id == nullptr;
						}
						else
						{
							int ratealgorithm = HALONMTA_RATE_ALGORITHM_DEFAULT;
							if (root["policy"]["then"]["rate"]["algorithm"].asString() == "fixedwindow")
								ratealgorithm = HALONMTA_RATE_ALGORITHM_FIXEDWINDOW;
							if (root["policy"]["then"]["rate"]["algorithm"].asString() == "tokenbucket")
								ratealgorithm = HALONMTA_RATE_ALGORITHM_TOKENBUCKET;

							error = !HalonMTA_queue_policy_update4(
								root["policy"]["id"].asString().c_str(),
								root["policy"]["then"]["concurrency"].isNumeric() ? root["policy"]["then"]["concurrency"].asUInt64() : 0,			// size_t concurrency,
								root["policy"]["then"]["rate"]["count"].isNumeric() ? root["policy"]["then"]["rate"]["count"].asUInt64() : 0,		// size_t tokens,
								root["policy"]["then"]["rate"]["interval"].isNumeric() ? root["policy"]["then"]["rate"]["interval"].asDouble() : 0, // double interval,
								ratealgorithm,																										// int ratealgorithm
								root["policy"]["then"]["connectinterval"].isNumeric() ? root["policy"]["then"]["connectinterval"].asDouble() : 0,	// double connectinterval,
								root["policy"]["then"]["tag"].isString() ? root["policy"]["then"]["tag"].asString().c_str() : nullptr,				// const char* tag,
								&properties[0],																										// const char* propv[],
								properties.size(),																									// size_t propl,
								root["policy"]["then"]["stop"].isBool() ? root["policy"]["then"]["stop"].asBool() : false,							// bool stop,
								root["policy"]["then"]["cluster"].isBool() ? root["policy"]["then"]["cluster"].asBool() : true,						// bool cluster,
								root["policy"]["ttl"].isNumeric() ? root["policy"]["ttl"].asDouble() : 0											// double ttl
							);
						}

						for (auto& i : properties)
							free((void*)i);

						if (error)
						{
							syslog(LOG_CRIT, "policyd-client: Failed to create policy: %s", root["policy"]["id"].asString().c_str());
							if (!ready)
								break;
						}

						uuid.insert({ UUIDType::POLICY, root["policy"]["id"].asString() });
					}
					else if (root["suspend"])
					{
						auto id = root["suspend"]["id"].asString();

						std::vector<const char*> properties;
						if (root["suspend"]["properties"])
						{
							for (auto i = root["suspend"]["properties"].begin(); i != root["suspend"]["properties"].end(); ++i)
							{
								properties.push_back(strdup(i.key().asCString()));
								properties.push_back(strdup(i->asCString()));
							}
						}

						if (uuid_last.find({ UUIDType::SUSPEND, id }) == uuid_last.end())
						{
							if (root["suspend"]["type"].asString() == "WARMUP")
							{
								if (root["suspend"]["localip"].isString())
								{
									warmups_mutex.lock();
									warmups[root["suspend"]["localip"].asString()]
										.push_back({ 0,
													 {},
													 id,
													 UUIDType::SUSPEND });
									warmups_mutex.unlock();
								}
								else
								{
									syslog(LOG_CRIT, "policy of typ warmup was missing localip");
								}
							}

							auto _id = HalonMTA_queue_suspend_add5(
								root["suspend"]["id"].asString().c_str(),
								root["suspend"]["transportid"].isString() ? root["suspend"]["transportid"].asString().c_str() : nullptr,		 // const char* transportid,
								root["suspend"]["localip"].isString() ? root["suspend"]["localip"].asString().c_str() : nullptr,				 // const char* localip,
								root["suspend"]["remoteip"].isString() ? root["suspend"]["remoteip"].asString().c_str() : nullptr,				 // const char* remoteip,
								root["suspend"]["remotemx"].isString() ? root["suspend"]["remotemx"].asString().c_str() : nullptr,				 // const char* remotemx,
								root["suspend"]["recipientdomain"].isString() ? root["suspend"]["recipientdomain"].asString().c_str() : nullptr, // const char* recipientdomain,
								root["suspend"]["jobid"].isString() ? root["suspend"]["jobid"].asString().c_str() : nullptr,					 // const char* jobid,
								root["suspend"]["grouping"].isString() ? root["suspend"]["grouping"].asString().c_str() : nullptr,				 // const char* grouping,
								root["suspend"]["tenantid"].isString() ? root["suspend"]["tenantid"].asString().c_str() : nullptr,				 // const char*tenantidtransportid,
								root["suspend"]["tag"].isString() ? root["suspend"]["tag"].asString().c_str() : nullptr,						 // const char* tag,
								&properties[0],																									 // const char* propv[],
								properties.size(),																								 // size_t propl,
								root["suspend"]["ttl"].isNumeric() ? root["suspend"]["ttl"].asDouble() : 0										 // double ttl
							);
							error = _id == nullptr;
						}

						for (auto& i : properties)
							free((void*)i);

						if (error)
						{
							syslog(LOG_CRIT, "policyd-client: Failed to create suspend: %s", root["suspend"]["id"].asString().c_str());
							if (!ready)
								break;
						}

						uuid.insert({ UUIDType::SUSPEND, root["suspend"]["id"].asString() });
					}
					else
					{
						syslog(LOG_CRIT, "policyd-client: Failed to create unsupported type");
						if (!ready)
							break;
						continue;
					}
				}
				if (root["action"].asString() == "UPDATE")
				{
					if (!root["policy"])
					{
						syslog(LOG_CRIT, "policyd-client: Failed to delete unsupported type");
						if (!ready)
							break;
						continue;
					}

					std::vector<const char*> properties;
					if (root["policy"]["then"]["properties"])
					{
						for (auto i = root["policy"]["then"]["properties"].begin(); i != root["policy"]["then"]["properties"].end(); ++i)
						{
							properties.push_back(strdup(i.key().asCString()));
							properties.push_back(strdup(i->asCString()));
						}
					}

					int ratealgorithm = HALONMTA_RATE_ALGORITHM_DEFAULT;
					if (root["policy"]["then"]["rate"]["algorithm"].asString() == "FIXEDWINDOW")
						ratealgorithm = HALONMTA_RATE_ALGORITHM_FIXEDWINDOW;
					if (root["policy"]["then"]["rate"]["algorithm"].asString() == "TOKENBUCKET")
						ratealgorithm = HALONMTA_RATE_ALGORITHM_TOKENBUCKET;

					error = !HalonMTA_queue_policy_update4(
						root["policy"]["id"].asString().c_str(),
						root["policy"]["then"]["concurrency"].isNumeric() ? root["policy"]["then"]["concurrency"].asUInt64() : 0,			// size_t concurrency,
						root["policy"]["then"]["rate"]["count"].isNumeric() ? root["policy"]["then"]["rate"]["count"].asUInt64() : 0,		// size_t tokens,
						root["policy"]["then"]["rate"]["interval"].isNumeric() ? root["policy"]["then"]["rate"]["interval"].asDouble() : 0, // double interval,
						ratealgorithm,																										// int ratealgorithm
						root["policy"]["then"]["connectinterval"].isNumeric() ? root["policy"]["then"]["connectinterval"].asDouble() : 0,	// double connectinterval,
						root["policy"]["then"]["tag"].isString() ? root["policy"]["then"]["tag"].asString().c_str() : nullptr,				// const char* tag,
						&properties[0],																										// const char* propv[],
						properties.size(),																									// size_t propl,
						root["policy"]["then"]["stop"].isBool() ? root["policy"]["then"]["stop"].asBool() : false,							// bool stop,
						root["policy"]["then"]["cluster"].isBool() ? root["policy"]["then"]["cluster"].asBool() : true,						// bool cluster,
						root["policy"]["ttl"].isNumeric() ? root["policy"]["ttl"].asDouble() : 0											// double ttl
					);

					for (auto& i : properties)
						free((void*)i);

					if (error)
					{
						syslog(LOG_CRIT, "policyd-client: Failed to update policy: %s", root["policy"]["id"].asString().c_str());
						if (!ready)
							break;
					}
				}
				if (root["action"].asString() == "DELETE")
				{
					std::string id;
					if (root["policy"])
					{
						id = root["policy"]["id"].asString();
						error = !HalonMTA_queue_policy_delete(id.c_str());
						if (error)
						{
							syslog(LOG_CRIT, "policyd-client: Failed to delete policy: %s", root["policy"]["id"].asString().c_str());
							if (!ready)
								break;
						}
						uuid.erase({ UUIDType::POLICY, id });
						cleanupWarmup(UUIDType::POLICY, id);
					}
					else if (root["suspend"])
					{
						id = root["suspend"]["id"].asString();
						error = !HalonMTA_queue_suspend_delete(id.c_str());
						if (error)
						{
							syslog(LOG_CRIT, "policyd-client: Failed to delete suspend: %s", root["suspend"]["id"].asString().c_str());
							// if (!ready)
							//   break;
						}
						uuid.erase({ UUIDType::SUSPEND, id });
						cleanupWarmup(UUIDType::SUSPEND, id);
					}
					else
					{
						syslog(LOG_CRIT, "policyd-client: Failed to delete unsupported type");
						if (!ready)
							break;
					}
				}
				if (root["action"].asString() == "SYNCED")
				{
					for (const auto& ul : uuid_last)
					{
						if (uuid.find(ul) == uuid.end())
						{
							switch (ul.type)
							{
								case UUIDType::POLICY:
								{
									bool ret = HalonMTA_queue_policy_delete(ul.id.c_str());
									if (!ret)
										syslog(LOG_CRIT, "policyd-client: Failed to delete policy: %s", ul.id.c_str());
									cleanupWarmup(UUIDType::POLICY, ul.id);
								}
								break;
								case UUIDType::SUSPEND:
								{
									bool ret = HalonMTA_queue_suspend_delete(ul.id.c_str());
									if (!ret)
										syslog(LOG_CRIT, "policyd-client: Failed to delete suspend: %s", ul.id.c_str());
									cleanupWarmup(UUIDType::SUSPEND, ul.id);
								}
								break;
							}
						}
					}

					if (error)
						break;

					ready = true;
				}
			}
			else if (res == CURLE_AGAIN)
			{
				usleep(100000); // 100ms
				continue;
			}
			else
			{
				syslog(LOG_CRIT, "policyd-client: %s", curl_easy_strerror(res));
				break;
			}
		}

		// saving old rules...
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
bool Halon_init(HalonInitContext* hic)
{
	HalonConfig* cfg;
	HalonMTA_init_getinfo(hic, HALONMTA_INIT_CONFIG, nullptr, 0, &cfg, nullptr);
	const char* address_ = HalonMTA_config_string_get(HalonMTA_config_object_get(cfg, "address"), nullptr);
	if (address_)
		Config.address = address_;

	websocketThread = std::thread([] { websocketWorker(); });
	while (!ready && !error)
		usleep(100000);
	if (error)
	{
		syslog(LOG_CRIT, "policyd-client: Failed to sync policies");
		return false;
	}
	return true;
}

HALON_EXPORT
bool Halon_queue_insert_callback(HalonQueueContext* hqc)
{
	char** localips;
	size_t localips_count;
	HalonMTA_queue_getinfo(hqc, HALONMTA_INFO_LOCALIPS, nullptr, 0, &localips, &localips_count);

	bool modified = false;
	HalonQueueMessage* hqm = nullptr;
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
		for (const auto& condition : w->second)
		{
			std::vector<std::string> compare;
			for (const auto& p : (std::vector<std::pair<size_t, int>>){
					 { HALONMTA_QUEUE_TRANSPORTID, HALONMTA_MESSAGE_TRANSACTIONID },
					 { HALONMTA_QUEUE_REMOTEIP, HALONMTA_MESSAGE_REMOTEIP },
					 { HALONMTA_QUEUE_REMOTEMX, HALONMTA_MESSAGE_REMOTEMX },
					 { HALONMTA_QUEUE_RECIPIENTDOMAIN, HALONMTA_MESSAGE_RECIPIENTDOMAIN },
					 { HALONMTA_QUEUE_JOBID, HALONMTA_MESSAGE_JOBID },
					 { HALONMTA_QUEUE_GROUPING, HALONMTA_MESSAGE_GROUPING },
					 { HALONMTA_QUEUE_TENANTID, HALONMTA_MESSAGE_TENANTID },
				 })
			{
				if (condition.fields & p.first)
				{
					if (value_cache.find(p.first) == value_cache.end())
					{
						if (!hqm)
							HalonMTA_queue_getinfo(hqc, HALONMTA_INFO_MESSAGE, nullptr, 0, &hqm, nullptr);
						size_t vl;
						const char* v;
						HalonMTA_message_getinfo(hqm, p.second, nullptr, 0, &v, &vl);
						value_cache[p.first] = std ::string(v, vl);
					}
					compare.push_back(value_cache[p.first]);
				}
			}
			if (condition.values == compare)
			{
				match = true;
				break;
			}
		}

		if (!match)
			modified = true;
		else
			localips_touse.push_back(localips[i]);
	}
	warmups_mutex.unlock();

	if (modified)
	{
		if (localips_touse.empty())
		{
			HalonHSLValue* ret;
			HalonMTA_queue_getinfo(hqc, HALONMTA_INFO_RETURN, NULL, 0, &ret, NULL);
			HalonMTA_hsl_value_set(ret, HALONMTA_HSL_TYPE_ARRAY, nullptr, 0);
			HalonHSLValue *key, *val;
			HalonMTA_hsl_value_array_add(ret, &key, &val);
			HalonMTA_hsl_value_set(key, HALONMTA_HSL_TYPE_STRING, "error", 0);
			HalonMTA_hsl_value_set(val, HALONMTA_HSL_TYPE_STRING, "NO_IPS", 0);
			return false;
		}
		const char** localips2 = new const char*[localips_touse.size()];
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
