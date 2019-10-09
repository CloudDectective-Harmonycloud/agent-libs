# (C) Sysdig, Inc. 2016-2017
# All rights reserved
# Licensed under Simplified BSD License (see LICENSE)

# stdlib
import logging
import math

# 3rd party
import requests

# Prometheus python lib
from prometheus_client.parser import text_string_to_metric_families

# project
from checks import AgentCheck
from sdchecks import AppCheckDontRetryException

class Prometheus(AgentCheck):

    DEFAULT_TIMEOUT = 1

    def __init__(self, name, init_config, agentConfig, instances=None):
        AgentCheck.__init__(self, name, init_config, agentConfig, instances)
        self.metric_history = {}

    def __dump_histogram__(self, keyvals, keys, desc):
        logging.info('======== %s ========' % (desc))
        for k in keys:
            logging.info('[%s]: %s' % (repr(k), repr(keyvals[k])))
        logging.info('======== %s ========' % (desc))

    def __check_metric_limits(self, max_metrics, num_metrics, pid, url):
        if max_metrics and num_metrics >= max_metrics:
            logging.info('Prometheus "max_metrics_per_process" limit(%d) exceeded for process:%d with url:%s ' % (max_metrics, pid, url))
            return True
        return False

    def __check_tag_limits(self, max_tags, num_tags, pid, url, mname):
        if max_tags and num_tags >= max_tags:
            logging.warning('Prometheus max_tags limit exceeded process:%d url:%s metric:%s max_tags:%d num_tags:%d' % (pid, url, mname, max_tags, num_tags))
            return True
        return False

    def check(self, instance):
        if 'url' not in instance:
            raise Exception('Prometheus instance missing "url" value.')

        # Load values from the instance config
        query_url = instance['url']
        max_metrics = instance.get('max_metrics')
        if max_metrics:
            max_metrics = int(max_metrics)
        max_tags = instance.get('max_tags')
        if max_tags:
            max_tags = int(max_tags)
        ret_histograms = instance.get("histograms", False)

        ingest_raw = instance.get("ingest_raw", False)
        ingest_calculated = instance.get("ingest_calculated", not ingest_raw)

        default_timeout = self.init_config.get('default_timeout', self.DEFAULT_TIMEOUT)
        timeout = float(instance.get('timeout', default_timeout))
        ssl_verify = instance.get('ssl_verify', False)
        auth = {
            "username": instance.get('username', False),
            "password": instance.get('password', False),
            "auth_token_path": instance.get('auth_token_path', False),
            "auth_cert_path": instance.get('auth_cert_path', False),
            "auth_key_path": instance.get('auth_key_path', False)
        }
        conf_tags = instance.get('tags', [])
        pid = instance.get('pid',0)

        metrics = self.get_prometheus_metrics(query_url, timeout, ssl_verify, auth, "prometheus", conf_tags)
        num = 0
        try:
            for family in metrics:
                parse_sum = None
                parse_count = None
                if max_metrics and self.__check_metric_limits(max_metrics, num, pid, query_url):
                    break

                name = family.name
                hists = dict()

                for sample in family.samples:
                    if self.__check_metric_limits(max_metrics, num, pid, query_url):
                        break
                    # getting name, tags, value this way to be compatible with old prometheus_client
                    (sname, stags, value) = sample[0:3]

                    if sname is None or value is None:
                        logging.debug('prometheus: parse missed name or value: %s' % (repr(sample)))
                        continue

                    if ingest_raw:
                        rawtags = ['{}:{}'.format(k,v) for k,v in stags.iteritems()]

                        if self.__check_tag_limits(max_tags, len(rawtags), pid, query_url, sname):
                            break

                        # No check here for NaN values, as we do allow them for raw prometheus metrics.
                        self.prometheus_raw(family.type, sname, value, rawtags)
                        num += 1
                        if self.__check_metric_limits(max_metrics, num, pid, query_url):
                            break

                    if not ingest_calculated:
                        continue

                    # convert the dictionary of tags into a list of '<name>:<val>' items
                    # also exclude 'quantile' as a key as it isn't a tag
                    reserved_tags = []
                    if family.type == 'summary':
                        reserved_tags.append('quantile')
                    elif family.type == 'histogram':
                        reserved_tags.append('le')
                    tags = ['{}:{}'.format(k,v) for k,v in stags.iteritems() if k not in reserved_tags]

                    if self.__check_tag_limits(max_tags, len(tags), pid, query_url, sname):
                        break

                    hist_entry = None
                    if (family.type == 'histogram') and (ret_histograms != False):
                        hkey = repr(tags)
                        if hkey not in hists:
                            hists[hkey] = {'tags':tags, 'buckets':dict()}
                        hist_entry = hists.get(hkey)

                    # First handle summary
                    # Unused, see above
                    if family.type == 'histogram' or family.type == 'summary':
                        if sname == name + '_sum':
                            parse_sum = value
                        elif sname == name + '_count':
                            parse_count = value
                        else:
                            if (family.type == 'histogram'):
                                if (ret_histograms == False) or ('le' not in stags):
                                    continue
                                bkey = stags['le']
                                if (bkey == '+Inf') or (type(eval(bkey)) in [type(int()), type(float())]):
                                    bkey = float(bkey)
                                else:
                                    logging.error('prom: Unexpected bucket label type/val for %s{%s}' % (sname, stags))
                                hist_entry['buckets'][bkey] = value
                            elif ('quantile' in stags) and (not math.isnan(value)):
                                quantile = int(float(stags['quantile']) * 100)
                                qname = '%s.%dpercentile' % (name, quantile)
                                # logging.debug('prom: Adding quantile gauge %s' %(qname))
                                self.gauge(qname, value, tags + conf_tags)
                                num += 1
                                continue
    
                        if parse_sum != None and parse_count != None:
                            prev = self.metric_history.get(name+str(tags), None) 
                            val = None
                            # The average value over our sample period is:
                            # val = (sum - prev_sum) / (count - prev_count)
                            # We can only find the current average if we have
                            # a previous sample and the count has increased
                            # Otherwise we can't send the current average,
                            # but we'll still send the count (as a rate)
                            if prev and prev.get("sum") != None and prev.get("count") != None:
                                dcnt = parse_count - prev.get("count")
                                if dcnt > 0:
                                    val = (parse_sum - prev.get("sum")) / dcnt
                                elif dcnt < 0:
                                    logging.info('prom: Descending count for %s%s' %(name, repr(tags)))
                            if val != None and not math.isnan(val):
                                # logging.debug('prom: Adding diff-avg %s%s = %s' %(name, repr(tags), str(val)))
                                self.gauge(name+".avg", val, tags + conf_tags)

                            self.rate(name+".count", parse_count, tags + conf_tags)
                            self.metric_history[name+str(tags)] = { "sum":parse_sum, "count":parse_count }
                            # reset refs to sum and count samples in order to
                            # have them point to other segments within the same
                            # family
                            parse_sum = None
                            parse_count = None
                            num += 1
                    elif (family.type == 'counter') and (not math.isnan(value)):
                        # logging.debug('prom: adding counter with name %s' %(name))
                        self.rate(name, value, tags + conf_tags)
                        num += 1
                    elif not math.isnan(value):
                        # Could be a gauge or untyped value, which we treat as a gauge for now
                        # logging.debug('prom: adding gauge with name %s' %(name))
                        self.gauge(name, value, tags + conf_tags)
                        num += 1

                # process the histograms and submit the buckets
                for k,v in hists.iteritems():
                    logging.debug('prom: processing histogram for %s%s' % (name, k))
                    bkeys = sorted(v['buckets'].iterkeys())

                    #self.__dump_histogram__(v['buckets'], bkeys, 'pre-processing')

                    # convert the histograms with cumulative counter to absolute counters
                    if len(v['buckets']) > 1:
                        for i in xrange(len(bkeys)-1, 0, -1):
                            v['buckets'][bkeys[i]] -= v['buckets'][bkeys[i-1]]

                    #self.__dump_histogram__(v['buckets'], bkeys, 'post-processing')

                    self.buckets(name, v['buckets'], v['tags'])
                    num += 1

        # text_string_to_metric_families() generator can raise exceptions
        # for parse values. Treat them all as failures and don't retry.
        except Exception as ex:
            raise AppCheckDontRetryException(ex)

    def get_prometheus_metrics(self, url, timeout, ssl_verify, auth, name, conf_tags):
        try:
            if auth.get("auth_token_path"):
                with open(auth["auth_token_path"], 'r') as file:
                    auth_token = file.read()
                    r = requests.get(url, timeout=timeout, verify=ssl_verify, headers = {"Authorization":"Bearer " + auth_token})
            elif auth.get("auth_cert_path") and auth.get("auth_key_path"):
                cert = (auth["auth_cert_path"], auth["auth_key_path"])
                r = requests.get(url, timeout=timeout, verify=ssl_verify, cert=cert)
            elif auth.get("username") and auth.get("password"):
                r = requests.get(url, timeout=timeout, verify=ssl_verify, auth=(auth["username"], auth["password"]))
            else:
                r = requests.get(url, timeout=timeout, verify=ssl_verify)
            r.raise_for_status()
        except requests.exceptions.Timeout:
            # If there's a timeout
            self.service_check(name, AgentCheck.CRITICAL,
                message='%s timed out after %s seconds.' % (url, timeout),
                tags = ["url:{0}".format(url)] + conf_tags)
            raise Exception("Timeout when hitting %s" % url)

        except requests.exceptions.HTTPError:
            self.service_check(name, AgentCheck.CRITICAL,
                message='%s returned a status of %s' % (url, r.status_code),
                tags = ["url:{0}".format(url)] + conf_tags)
            raise AppCheckDontRetryException("Got %s when hitting %s" % (r.status_code, url))
        except (ValueError, requests.exceptions.ConnectionError) as ex:
            raise AppCheckDontRetryException(ex)

        else:
            self.service_check(name, AgentCheck.OK,
                tags = ["url:{0}".format(url)] + conf_tags)

        try:
            metrics = text_string_to_metric_families(r.text)
        # Treat all parse errrors as failures and don't retry.
        except Exception as ex:
            raise AppCheckDontRetryException(ex)
        return metrics
