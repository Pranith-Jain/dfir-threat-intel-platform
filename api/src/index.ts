import { Hono } from 'hono';
import { cors } from 'hono/cors';
import type { Env } from './env';
import { iocCheckHandler } from './routes/ioc';
import { iocEnrichDeepHandler } from './routes/ioc-enrich-deep';

import { domainLookupHandler } from './routes/domain';
import { intodnsSnapshotHandler, intodnsExplainHandler } from './routes/intodns';
import {
  intodnsBlacklistHandler,
  intodnsSenderRequirementsHandler,
  intodnsSmtpTlsHandler,
  intodnsFcrdnsHandler,
  intodnsDnssecHandler,
  intodnsSecHeadersHandler,
  intodnsBadgeHandler,
  intodnsDebugEmailHandler,
} from './routes/intodns-specialist';
import { phishingAnalyzeHandler } from './routes/phishing';
import { urlRiskAnalyzeHandler } from './routes/url-risk';
import { exposureScanHandler } from './routes/exposure';
import { exposureCheckHandler } from './routes/exposure-check';
import { fileAnalyzeHandler } from './routes/file';
import { feedProxyHandler } from './routes/feeds';
import { ctiParseHandler } from './routes/cti';
import { osvScanHandler } from './routes/osv';
import { depsDevPackageHandler } from './routes/supply-chain';
import { privacyInspectHandler } from './routes/privacy';
import { iocFeedSummaryHandler } from './routes/ioc-feeds';
import { cveSearchHandler } from './routes/cve';
import { cveBatchLookupHandler } from './routes/cve-batch';
import { mitreTechniqueHandler } from './routes/mitre';
import { atlasTechniqueHandler } from './routes/atlas';
import { asnLookupHandler } from './routes/asn';
import { breachRangeHandler, breachEmailHandler, breachDomainHandler } from './routes/breach';
import { urlPreviewHandler } from './routes/url-preview';
import { takeoverCheckHandler } from './routes/takeover';
import { threatMapHandler } from './routes/threat-map';
import { feedsAggregateHandler } from './routes/feeds-aggregate';
import { detectionRulesHandler } from './routes/detection-rules';
import { breachDisclosuresHandler } from './routes/breach-disclosures';
import { ransomwareRecentHandler } from './routes/ransomware-recent';
import { ransomwareMapHandler } from './routes/ransomware-map';
import { cryptoTraceHandler } from './routes/crypto-trace';
import {
  torStatusHandler,
  torFetchOnionHandler,
  torScrapeOnionHandler,
  torSearchOnionHandler,
  torExitNodesHandler,
  torExitCheckHandler,
  torExitDetailsHandler,
  onionLookupHandler,
  btcAbuseCheckHandler,
} from './routes/darknet';
import {
  tracerExpandHandler,
  tracerLabelHandler,
  tracerLabelAddHandler,
  tracerCalldataHandler,
  tracerGraphSaveHandler,
  tracerGraphListHandler,
  tracerGraphGetHandler,
  tracerGraphDeleteHandler,
} from './routes/tracer';
import {
  cryptoWatchAddHandler,
  cryptoWatchListHandler,
  cryptoWatchRemoveHandler,
  cryptoAlertsHandler,
} from './routes/crypto-monitor';
import { abuseRssHandler } from './routes/abuse-rss';
import {
  threatSignalRssHandler,
  threatSignalRssXmlHandler,
  openSourceMalwareRssHandler,
  openSourceMalwareRssXmlHandler,
  rssAggregateHandler,
  rssSourcesHandler,
} from './routes/threatsignal-rss';
import { mtiRansomwareRssHandler } from './routes/mti-ransomware-rss';
import { ransomwareMergedRssHandler } from './routes/ransomware-merged-rss';
import { mtiHandler, mtiDnsHandler } from './routes/mti';
import { mispProxyHandler } from './routes/misp';
import { waybackCdxHandler } from './routes/wayback';
import { builtwithHandler } from './routes/builtwith';
import { ctLogHandler } from './routes/ct-log';
import { waybackAdvancedHandler } from './routes/wayback-advanced';
import { threatPulseHandler } from './routes/threat-pulse';
import { firmsUkmtoHandler } from './routes/firms-ukmto';
import { ipGeoHandler } from './routes/ip-geo';
import { stixFetchHandler } from './routes/stix-fetch';
import { certSearchHandler } from './routes/cert-search';
import { webScanHandler } from './routes/web-scan';
import { onionWatchHandler } from './routes/onion-watch';
import {
  telegramFeedHandler,
  tgLiveSearchHandler,
  telegramCustomChannelsGetHandler,
  telegramCustomChannelsPostHandler,
  telegramCustomChannelsDeleteHandler,
  telegramBotStatusHandler,
  telegramBotRegisterHandler,
  pollBotUpdatesWithResult,
} from './routes/telegram-feed';
import { telegramSearchHandler, telegramChannelMetaHandler } from './routes/telegram-search';
import { cveRecentHandler } from './routes/cve-recent';
import { cveDigestHandler } from './routes/cve-digest';
import { cveDigestCsvHandler, cveDigestRssHandler, cveDigestFeedUrlHandler } from './routes/cve-digest-export';
import {
  promptintelHealthHandler,
  promptintelTaxonomyHandler,
  promptintelPromptsHandler,
  promptintelEntryHandler,
} from './routes/promptintel';
import { cveThreatMapHandler } from './routes/cve-threat-map';
import { cvePocScanHandler } from './routes/cve-poc-scan';
import { cvePocMapHandler } from './routes/cve-poc-map';
import { cyberNewsHandler } from './routes/cyber-news';
import { cveHealthHandler } from './routes/cve-health';
import { socCveReportHandler, socCveReportJsonHandler } from './routes/soc-cve-report';
import { phishingUrlsHandler } from './routes/phishing-urls';
import { cryptoScamFeedHandler } from './routes/crypto-scam-feed';
import { actorUsernamesHandler, actorUsernamesStatsHandler } from './routes/actor-usernames';
import { usernameOsnitHandler, usernamePatternsHandler, usernameProfileHandler } from './routes/username-osint';
import { phoneOsintHandler } from './routes/phone-osint';
import { checkHandler as osmCheckHandler, latestHandler as osmLatestHandler } from './routes/opensourcemalware';
import { reverseImageSearchHandler } from './routes/reverse-image-search';
import { wifiInvestigationHandler } from './routes/wifi-investigation';
import { scrapedintelUsernamesHandler } from './routes/scrapedintel-usernames';
import { phishingWordlistsHandler } from './routes/phishing-wordlists';
import { malwareSamplesHandler } from './routes/malware-samples';
import { malwareCapabilitiesHandler } from './routes/malware-capabilities';
import { infraSearchHandler } from './routes/infra-search';
import { redditFeedHandler } from './routes/reddit-feed';
import { xFeedHandler } from './routes/x-feed';
import { aiHoneypotFeedHandler } from './routes/ai-honeypot-feed';
import { feedStatusHandler } from './routes/feed-status';
import { iocCorrelationHandler } from './routes/ioc-correlation';
import { actorTimelineHandler } from './routes/actor-timeline';
import { victimReleaksHandler } from './routes/victim-releaks';
import { liveIocsHandler } from './routes/live-iocs';
import { aiLlmIntelHandler } from './routes/ai-llm-intel';
import { detectionsHandler } from './routes/detections';
import { deepDarkCtiHandler } from './routes/deepdarkcti';
import { stealerForumIntelHandler } from './routes/stealer-forum-intel';
import { breachForumsHandler } from './routes/breach-forums';
import { breachForumStatusHandler } from './routes/breach-forum-status';
import { breachCoverageHandler } from './routes/breach-coverage';
import {
  cyberpulseIncidentsHandler,
  cyberpulseStatsHandler,
  cyberpulseTrendingHandler,
  cyberpulseScanLogHandler,
  cyberpulseIngestHandler,
  cyberpulseScanHandler,
} from './routes/cyberpulse';
import { negotiationsHandler, negotiationTranscriptHandler } from './routes/negotiations';
import { ransomwareLiveHandler } from './routes/ransomwarelive';
import { kqlIndexHandler, kqlViewHandler } from './routes/ransomwarelive-kql';
import { writeupsHandler } from './routes/writeups';
import { cybercrimeHandler } from './routes/cybercrime';
import { iocExplainHandler, iocRuleHandler } from './routes/ioc-verdict';
import { globalPulseHandler } from './routes/global-pulse';
import {
  ironsightAlertsHandler,
  ironsightFlightsHandler,
  ironsightStrikesHandler,
  ironsightRegionalHandler,
  ironsightMarketsHandler,
  ironsightCryptoHandler,
  ironsightPolymarketHandler,
  ironsightFiresHandler,
} from './routes/ironsight';
import { threatAnalysisHandler } from './routes/threat-analysis';
import { iocExtractionHandler } from './routes/ioc-extraction';
import { mitreMappingHandler } from './routes/mitre-mapping';
import { countryIntelHandler } from './routes/country-intel';
import { eventCorrelationHandler } from './routes/event-correlation';
import { campaignTrackerHandler } from './routes/campaign-tracker';
import { feedQualityHandler as assessFeedQualityHandler } from './routes/feed-quality';
import { storyClusterHandler } from './routes/story-cluster';
import { alertCheckHandler } from './routes/alert-check';
import { researchDigestHandler } from './routes/research-digest';
import { darkwebIntelHandler } from './routes/darkweb-intel';
import { knowledgeGraphHandler } from './routes/knowledge-graph';
import {
  webamonSearchHandler,
  webamonScanHandler,
  webamonReportsHandler,
  webamonReportHandler,
  webamonScreenshotHandler,
  webamonDomainHandler,
  webamonServerHandler,
  webamonResourceHandler,
} from './routes/webamon';
import {
  webamonCampaignsHandler,
  webamonCampaignStatsHandler,
  webamonCampaignDomainsHandler,
  webamonChangesHandler,
  webamonClustersHandler,
  webamonCampaignIntelHandler,
} from './routes/webamon-campaigns';
import {
  listBriefingsHandler,
  getBriefingHandler,
  todayBriefingHandler,
  buildBriefingHandler,
  backfillBriefingsHandler,
  sweepBriefingsHandler,
  deleteBriefingHandler,
  pruneEmptyBriefingsHandler,
  briefingsForActorHandler,
  briefingPrintHandler,
  briefingIocsTxtHandler,
  briefingsRelatedHandler,
} from './routes/briefings';
import { briefingRenderHandler } from './routes/briefing-render';
import { briefingsRssHandler } from './routes/briefings-rss';
import {
  submitFeedbackHandler,
  getFeedbackHandler,
  submitAnnotationHandler,
  getAnnotationsHandler,
  feedbackSummaryHandler,
} from './routes/briefing-feedback';
import {
  listExternalResourcesHandler,
  createExternalResourceHandler,
  deleteExternalResourceHandler,
} from './routes/external-resources';
import { snapshotHandler } from './routes/snapshot';
import { iocSnapshotHandler } from './routes/ioc-snapshot';
import { intelDashboardHandler } from './routes/intel-dashboard';
import { threatHuntHandler } from './routes/threat-hunt';
import { huntV2Handler } from './routes/hunt-v2';
import { phishingAnalyzeAutoHandler } from './routes/phishing-auto-analyze';
import { registerBlogRoutes } from './routes/blog-public';
import { pageViewsHandler } from './routes/pageviews';
import { registerAdminRoutes } from './routes/case-study-admin';

import { c2TrackerHandler } from './routes/c2-tracker';
import {
  intelBundleHandler,
  intelBundlePostHandler,
  intelBundleBuildHandler,
  intelBundleExportHandler,
  intelBundleByIdHandler,
  intelBundleAdminHandler,
} from './routes/intel-bundle';
import { googleDorksHandler } from './routes/google-dorks';
import { emailRepHandler } from './routes/email-rep';
import {
  blocklistPfSenseHandler,
  blocklistIptablesHandler,
  blocklistSuricataHandler,
  blocklistMetaHandler,
} from './routes/blocklists';
import { fetchPageHandler, fingerprintHandler } from './routes/phishing-fingerprint';
import { unifiedSearchHandler } from './routes/unified-search';
import { unifiedSearchSummarizeHandler } from './routes/unified-search-summarize';
import { aggregatedFeedsHandler } from './routes/aggregated-feeds';
import { malwareFamilyListHandler, malwareFamilyDetailHandler } from './routes/malware-iocs';
import { feedCatalogHandler } from './routes/feed-catalog';
import { yaraHubListHandler, yaraHubRuleHandler } from './routes/yara-hub';
import {
  listInvestigationsHandler,
  createInvestigationHandler,
  getInvestigationHandler,
  updateInvestigationHandler,
  deleteInvestigationHandler,
  addObservableHandler,
  removeObservableHandler,
  addTaskHandler,
  updateTaskHandler,
  addNoteHandler,
} from './routes/investigations';
import {
  listFeedJobsHandler,
  createFeedJobHandler,
  updateFeedJobHandler,
  deleteFeedJobHandler,
  runFeedJobHandler,
  getFeedJobHistoryHandler,
  getFeedJobsHistoryAllHandler,
} from './routes/feed-scheduler';
import {
  listObservablesHandler,
  getObservableHandler,
  saveObservableHandler,
  updateObservableHandler,
  deleteObservableHandler,
  addObservableNoteHandler,
  deleteObservableNoteHandler,
  getObservableTagsHandler,
} from './routes/observable-db';
import {
  listVaultSamplesHandler,
  getVaultSampleHandler,
  uploadVaultSampleHandler,
  updateVaultSampleHandler,
  deleteVaultSampleHandler,
  downloadVaultSampleHandler,
  getVaultFamiliesHandler,
  getVaultTagsHandler,
} from './routes/malware-vault';
import { copilotInvestigateHandler } from './routes/copilot';
import {
  copilotChatHandler,
  copilotChatStreamHandler,
  copilotChatHistoryHandler,
  copilotChatListHandler,
  copilotChatDeleteHandler,
  copilotChatCancelHandler,
} from './routes/copilot-chat';
import { copilotPivotHandler } from './routes/copilot-pivots';
import { copilotFollowUpsHandler } from './routes/copilot-followups';
import { copilotBulkIocHandler } from './routes/copilot-bulk-ioc';
import { copilotRulesSaveHandler, copilotRulesListHandler, copilotRulesDeleteHandler } from './routes/copilot-rules';
import { ssvcTriageHandler, ssvcGetHandler, ssvcStatsHandler } from './routes/ssvc-triage';
import { dossierHandler, dossierGetHandler } from './routes/dossier';
import {
  watchlistActorsListHandler,
  watchlistActorsAddHandler,
  watchlistActorsDeleteHandler,
  watchlistActorActivityHandler,
  watchlistDigestGenerateHandler,
  watchlistDigestsListHandler,
  watchlistDigestGetHandler,
} from './routes/watchlist';
import {
  veraChatHandler,
  veraChatModesHandler,
  veraChatRolesHandler,
  veraChatStreamHandler,
  veraChatHistoryHandler,
  veraSessionsListHandler,
  veraChatDeleteHandler,
  veraChatCancelHandler,
} from './routes/vera';
import { stixBundlesHandler } from './routes/stix-bundles';
import { actionableIocsHandler, createIocTypeHandler } from './routes/actionable-iocs';
import { observeHandler } from './routes/observe';
import { buildReportHandler, getReportHandler, streamReportHandler } from './routes/report';
import { automationRunHandler } from './routes/automation';
import { dashboardHandler, getWatchlistHandler, updateWatchlistHandler } from './routes/dashboard';
import { maltiverseSearchHandler } from './routes/maltiverse';
import { inquestSearchHandler } from './routes/inquest';
import { hackertargetDnsHandler, hackertargetReverseIpHandler } from './routes/hackertarget';
import { radarDomainHandler } from './routes/cloudflare-radar';
import { certspotterSearchHandler } from './routes/certspotter';
import { triageSearchHandler } from './routes/triage';
import { reportParserHandler } from './routes/report-parser';
import { reportIngestHandler } from './routes/report-ingest';
import { domainRepHandler, domainMonitorHandler } from './routes/domain-advanced';
import { domainWebcheckHandler } from './routes/domain-webcheck';
import {
  domainHistoryHandler,
  domainChangesHandler,
  domainPivotHandler,
  domainHistoryStatsHandler,
  domainRegistrantSearchHandler,
  domainSnapshotHandler,
} from './routes/domain-history';
import { openDirectoryScanHandler } from './routes/open-directory';
import { exposedHostHandler } from './routes/exposed-host';
import { iocLifecycleHandler, iocLifecycleTrendingHandler, iocLifecycleStatsHandler } from './routes/ioc-lifecycle';
import { ruleGeneratorHandler, ruleValidateHandler } from './routes/yara-generator';
import { fplensAnalyzeHandler } from './routes/fplens';
import { ctWatchedListHandler, ctWatchAddHandler, ctWatchRemoveHandler, ctCertsHandler } from './routes/ct-monitor';
import {
  taxiiDiscoveryHandler,
  taxiiCollectionsHandler,
  taxiiCollectionHandler,
  taxiiObjectsHandler,
  taxiiAddObjectsHandler,
} from './routes/taxii';
import { stealerParserHandler } from './routes/stealer-parser';
import { bloomFilterHandler, bloomCheckHandler, bloomStatsHandler } from './routes/bloom-filter';
import {
  graphNodeHandler,
  graphPathHandler,
  graphCommunitiesHandler,
  graphStatsHandler,
  graphCrossReportHandler,
} from './routes/threat-graph';
import { graphIngestManualHandler } from './routes/graph-ingest';
import {
  temporalTimelineHandler,
  temporalCampaignsHandler,
  temporalVelocityHandler,
  temporalPredictHandler,
} from './routes/temporal-analysis';
import { attackChainHandler, attackChainTechniquesHandler } from './routes/attack-chain';
import {
  actorDnaMatchHandler,
  actorDnaGetHandler,
  actorDnaListHandler,
  actorDnaCompareHandler,
} from './routes/actor-dna';
import { campaignAnalyzeHandler, campaignTechniquesHandler } from './routes/campaign-lifecycle';
import {
  predictiveForecastsHandler,
  predictiveSectorRisksHandler,
  predictiveAttributionHandler,
  predictiveGapsHandler,
  predictiveReportHandler,
} from './routes/predictive-intel';
import {
  pirListHandler,
  pirDetailHandler,
  pirCreateHandler,
  pirUpdateHandler,
  pirDeleteHandler,
  pirAlertHandler,
  pirAlertListHandler,
  pirAlertAckHandler,
  pirAlertAckAllHandler,
  pirRoutingHandler,
  pirRelevantHandler,
} from './routes/pir';
import {
  feedbackCreateHandler,
  feedbackListHandler,
  feedbackAggregateHandler,
  feedbackDeleteHandler,
} from './routes/feedback';
import { sourceReliabilityHandler } from './lib/confidence';
import { maturityHandler } from './lib/maturity';
import { crossCampaignCorrelationHandler } from './routes/cross-campaign';

import {
  listWatchesHandler,
  createWatchHandler,
  updateWatchHandler,
  deleteWatchHandler,
  alertLogHandler,
} from './routes/watches';
import { rateLimit } from './lib/ratelimit';
import { burstLimitActorProfile } from './lib/actor-profile-burst';
import { apiKeyRateLimit } from './lib/api-key-ratelimit';
import { loadAttackIdIndex } from './lib/attack-id-lazy';
import { requestLogger } from './lib/request-logger';
import { csrfGuard } from './lib/csrf-guard';
import { errorHandler } from './lib/error-handler';
import { serverTiming } from './lib/server-timing';
import { requestId } from './lib/request-id';
import { authenticate, requireAdminRole } from './lib/auth';
import { requireAdminMiddleware } from './lib/admin-auth';
import { validate, validateText } from './lib/validate';
import { looseValidation } from './lib/loose-validate';
import { createExternalResourceSchema, telegramCustomChannelSchema } from './lib/schemas';
import {
  createApiKeyHandler,
  listApiKeysHandler,
  revokeApiKeyHandler,
  createSessionHandler,
  deleteSessionHandler,
} from './routes/admin-keys';
import { purgeCacheHandler } from './routes/admin-purge';
import { runRetentionHandler, telegramCleanupHandler } from './routes/admin-retention';
import { getXCookiesHandler, setXCookiesHandler, clearXCookiesHandler } from './routes/admin-x-cookies';
import { getXQidsHandler, setXQidsHandler, clearXQidsHandler } from './routes/admin-x-qids';
import { malpediaActorHandler, malpediaFamilyHandler, malpediaSearchHandler } from './routes/malpedia';
import { maltrailListHandler, maltrailFetchHandler } from './routes/maltrail';
import { actorEnrichHandler } from './routes/actor-enrich';
import { actorProfileHandler } from './routes/actor-profile';
import { actorEnrichOtxStreamHandler } from './routes/actor-enrich-stream';
import { certStreamHandler } from './routes/certstream';
import { campaignGeneratorHandler } from './routes/campaign-generator';
import { actorCvesHandler } from './routes/actor-cves';
import {
  saveCampaignHandler,
  listCampaignsHandler,
  getCampaignHandler,
  deleteCampaignHandler,
} from './routes/campaigns';
import { maltrailSyncHandler, listSkeletonActorsHandler, getSkeletonActorHandler } from './routes/maltrail-sync';
import { maliciousPackagesHandler } from './routes/malicious-packages';
import { depxFeedHandler, depxFeedStatsHandler, depxCheckHandler } from './routes/depx';
import { packageVerdictHandler } from './routes/package-verdict';
import { secretLeaksHandler } from './routes/secret-leaks';
import { feedQualityHandler as tifceFeedQualityHandler } from './routes/tifce';
import {
  agentDebugLlmHandler,
  agentInvestigateHandler,
  agentStateHandler,
  agentStreamHandler,
  agentSessionsHandler,
  agentMetricsHandler,
  agentProviderHealthHandler,
  agentMemoryHandler,
  agentKnowledgeGraphHandler,
  agentDeleteHandler,
} from './routes/agent';
import { agentHistoryHandler } from './routes/agent-history';
import { tieEnrichHandler, tieEnrichStateHandler, tieEnrichStreamHandler } from './routes/tie-enrich';
import { attackNavigatorHandler } from './routes/attack-navigator';
import { a3mMatrixHandler } from './routes/a3m-matrix';
import { d3fendMatrixHandler } from './routes/d3fend-matrix';
import { getSiteUrl } from './lib/site-config';
import { xTweetsHandler } from './routes/x-tweets';
import { xLiveHandler } from './routes/x-live';
import { xFirehoseHandler, xFirehoseProbeBatchHandler } from './routes/x-firehose';
import { xClaimsHandler } from './routes/x-claims';
import { xSearchHandler } from './routes/x-search';
import { relationshipGraphHandler } from './routes/relationship-graph';
import { ragIndexHandler, ragQueryHandler } from './routes/rag-index';
import { indexAllCorpora } from './routes/rag-corpus-index';
import { achHandler } from './routes/ach';
import { entityResolveHandler, entityExtractHandler, entityProfileHandler } from './routes/entity-resolver';
import { noveltyHandler, noveltyBatchHandler } from './routes/novelty';
import {
  assessmentCreateHandler,
  assessmentListHandler,
  assessmentDetailHandler,
  assessmentUpdateHandler,
  assessmentDeleteHandler,
} from './routes/assessments';
import { correlateHandler } from './routes/cross-correlate';
import { huntingQueryHandler } from './routes/hunting-queries';
import { sandboxLookupHandler } from './routes/sandbox';
import { sampleScanHandler } from './routes/sample-scan';
import { irPlaybookHandler } from './routes/ir-playbooks';
import { aiSummaryHandler } from './routes/ai-summary';
import { aiItemSummaryHandler } from './routes/ai-item-summary';
import { ttpExtractHandler } from './routes/ttp-extract';
import { fivewHandler } from './routes/fivew';
import { imageIocHandler } from './routes/image-ioc';
import { reportAnalyzerHandler } from './routes/report-analyzer';
import { reportAnalyzerRenderHandler } from './routes/report-analyzer-render';
import {
  listSavedReports,
  getSavedReport,
  saveReport,
  deleteSavedReport,
  correlateIocs,
  getTimeline,
  setBranding,
  shareSavedReport,
  unshareSavedReport,
  getSharedReport,
} from './routes/saved-reports';
import { leakIxSearchHandler } from './routes/leakix';
import { hostIntelHandler } from './routes/host';
import { proxyNovaSearchHandler } from './routes/proxynova';
import { mcpProxyHandler, mcpProxyOptions } from './routes/mcp-proxy';
import { identityProxyHandler } from './routes/identity-proxy';
import {
  hudsonRockSearchHandler,
  hudsonRockDomainHandler,
  hudsonRockDomainOverviewHandler,
  hudsonRockDiscoveryHandler,
  hudsonRockAssessmentHandler,
  hudsonRockInfectionAnalysisHandler,
  hudsonRockUsernameHandler,
  hudsonRockIpHandler,
  hudsonRockAccountHandler,
} from './routes/hudsonrock';
import { projectDiscoveryHandler } from './routes/projectdiscovery';
import {
  pdLeaksHandler,
  pdSubdomainsHandler,
  pdCvesHandler,
  pdCveDetailHandler,
} from './routes/projectdiscovery-intel';
import { orklSearchHandler, orklEntryHandler, orklInfoHandler } from './routes/orkl';
import { stopForumSpamHandler } from './routes/stopforumspam';
import { urlscanIpHandler } from './routes/urlscan-ip';
import { hackMyIpBreachHandler } from './routes/hackmyip';
import {
  telegramLeakSearchHandler,
  telegramDiscoveredChannelsHandler,
  telegramWatchedChannelsHandler,
  telegramApproveChannelHandler,
  telegramRejectChannelHandler,
  telegramLeakStatsHandler,
  telegramLeakGeoHandler,
} from './routes/telegram-leak-monitor';
import {
  telegramLeakBotWebhookHandler,
  telegramLeakBotRegisterHandler,
  telegramLeakBotWebhookStatusHandler,
} from './routes/telegram-leak-bot';
import { exploitDbHandler } from './routes/exploit-db';
import { fusionExposureHandler } from './routes/fusion-exposure';
import {
  riskRegisterListHandler,
  riskRegisterGetHandler,
  riskRegisterCreateHandler,
  riskRegisterUpdateHandler,
  riskRegisterDeleteHandler,
  riskRegisterStatsHandler,
} from './routes/risk-register';
import { attackPathGraphHandler } from './routes/attack-path-graph';
import {
  grcListFrameworks,
  grcGetFramework,
  grcUpdateFramework,
  grcListControls,
  grcGetControl,
  grcCreateControl,
  grcUpdateControl,
  grcDeleteControl,
  grcListEvidence,
  grcGetEvidence,
  grcCreateEvidence,
  grcUpdateEvidence,
  grcDeleteEvidence,
  grcStats,
} from './routes/grc-evidence';
import { vocList, vocGet, vocCreate, vocUpdate, vocDelete, vocStats } from './routes/vulnerability-ops';
import {
  ransomList,
  ransomGet,
  ransomCreate,
  ransomUpdate,
  ransomDelete,
  ransomStats,
} from './routes/ransomware-quant';
import {
  ptmListPatches,
  ptmGetPatch,
  ptmCreatePatch,
  ptmUpdatePatch,
  ptmDeletePatch,
  ptmListWindows,
  ptmGetWindow,
  ptmCreateWindow,
  ptmUpdateWindow,
  ptmDeleteWindow,
  ptmStats,
} from './routes/patch-task-mgr';
import {
  socListPlaybooks,
  socGetPlaybook,
  socCreatePlaybook,
  socUpdatePlaybook,
  socDeletePlaybook,
  socExecutePlaybook,
  socListRuns,
  socGetRun,
  socStats,
} from './routes/soc-automation';
import { securityUpdatesHandler } from './routes/security-updates';
import { cisaKevHandler } from './routes/cisa-kev';
import { certInHandler } from './routes/cert-in';
import { supplyChainAttacksHandler } from './routes/supply-chain-attacks';
import { k8sCveHandler } from './routes/k8s-cve';
import { mispGalaxyActorsHandler } from './routes/misp-galaxy-actors';
import { cloudThreatLandscapeHandler } from './routes/cloud-threat-landscape';
import { getRedHuntInsightsHandler } from './routes/redhunt-insights';
import { ransomwhereHandler } from './routes/ransomwhere';
import { disarmFrameworkHandler } from './routes/disarm-framework';
import { attackFlowLibraryHandler } from './routes/attack-flow-library';
import { volexityThreatIntelHandler } from './routes/volexity-threat-intel';
import {
  passiveDnsLookupHandler,
  passiveDnsReverseHandler,
  passiveDnsOverlapHandler,
  passiveDnsStatsHandler,
} from './routes/passive-dns';
import {
  iocWatchlistCreateHandler,
  iocWatchlistListHandler,
  iocWatchlistGetHandler,
  iocWatchlistDeleteHandler,
  iocWatchlistAlertsHandler,
  iocWatchlistStatsHandler,
} from './routes/ioc-watchlist';
import { gitHubSecurityHandler, gitHubSecurityRecentMetaHandler } from './routes/github-security';
import {
  getOwaspAiLandscapeHandler,
  getOwaspAiLandscapeMetaHandler,
  getCuratedToolboxHandler,
  getCuratedToolboxMetaHandler,
  getCuratedCertsHandler,
  getCuratedCertsMetaHandler,
} from './routes/landscape';
import { predictionsHandler } from './routes/predictions';
import { radarScanHandler, radarGetScanHandler, radarRecentHandler } from './routes/radar';
import { liveFeedExportHandler } from './routes/live-feed-export';

const app = new Hono<{ Bindings: Env }>();

// ── Radar (public, no auth required) ─────────────────────────────
app.use(
  '/api/v1/radar/*',
  cors({
    origin: (_, c) => getSiteUrl(c.env as { SITE_URL?: string }),
    allowHeaders: ['Content-Type'],
    allowMethods: ['GET', 'POST', 'OPTIONS'],
    maxAge: 86400,
  })
);
app.use('/api/v1/radar/*', requestId);
app.use('/api/v1/radar/*', csrfGuard);
app.use('/api/v1/radar/*', looseValidation());
app.use('/api/v1/radar/*', requestLogger);
app.use('/api/v1/radar/*', rateLimit);
app.post('/api/v1/radar/scan', radarScanHandler);
app.get('/api/v1/radar/scan/:id', radarGetScanHandler);
app.get('/api/v1/radar/recent', radarRecentHandler);

// ── CyberPulse scan ─────────────────────────────────────────────────────
// NOTE: the route itself is registered BELOW, after the global
// `authenticate('external-only')` chain (see below). It used to be registered
// here — above the auth middleware — which meant it carried NO authentication
// at all: no key, no same-origin check, no apiKeyRateLimit. It triggers
// runCyberPulseIngestion, which fans out to several upstream social feeds and
// WRITES to cyberpulse_incidents + cyberpulse_scan_log, so an unauthenticated
// caller could drive D1 writes and spend upstream quota on demand.
//
// It stays reachable from the site's own UI without a credential, because that
// UI is same-origin and the `external-only` mode exempts same-origin callers.
// Third parties now need an API key, matching every sibling /api/v1 route.
app.use('/api/v1/cyberpulse/*', rateLimit);

// ── IRONSIGHT (public, no auth required — proxy to free external APIs) ──
app.use(
  '/api/v1/ironsight/*',
  cors({
    origin: (_, c) => getSiteUrl(c.env as { SITE_URL?: string }),
    allowHeaders: ['Content-Type'],
    allowMethods: ['GET', 'OPTIONS'],
    maxAge: 300,
  })
);
app.use('/api/v1/ironsight/*', requestId);
app.use('/api/v1/ironsight/*', csrfGuard);
app.use('/api/v1/ironsight/*', looseValidation());
app.use('/api/v1/ironsight/*', requestLogger);
app.use('/api/v1/ironsight/*', rateLimit);
app.get('/api/v1/ironsight/alerts', ironsightAlertsHandler);
app.get('/api/v1/ironsight/flights', ironsightFlightsHandler);
app.get('/api/v1/ironsight/strikes', ironsightStrikesHandler);
app.get('/api/v1/ironsight/regional', ironsightRegionalHandler);
app.get('/api/v1/ironsight/markets', ironsightMarketsHandler);
app.get('/api/v1/ironsight/crypto', ironsightCryptoHandler);
app.get('/api/v1/ironsight/polymarket', ironsightPolymarketHandler);
app.get('/api/v1/ironsight/fires', ironsightFiresHandler);

// ── Dark Web OSINT (public, no auth — tor2web gateways are open) ──────────
app.use(
  '/api/v1/darkweb-osint/*',
  cors({
    origin: (_, c) => getSiteUrl(c.env as { SITE_URL?: string }),
    allowHeaders: ['Content-Type'],
    allowMethods: ['GET', 'OPTIONS'],
    maxAge: 300,
  })
);
app.use('/api/v1/darkweb-osint/*', requestId);
app.use('/api/v1/darkweb-osint/*', csrfGuard);
app.use('/api/v1/darkweb-osint/*', looseValidation());
app.use('/api/v1/darkweb-osint/*', requestLogger);
// The crawl handler fans out up to ~50 subrequests (tor2web gateways); without
// this it bypassed the global chain (mounted above it) and was unlimited.
app.use('/api/v1/darkweb-osint/*', rateLimit);
app.route('/api/v1', darkwebOsintRouter);

app.use(
  '/api/v1/*',
  cors({
    origin: (_, c) => getSiteUrl(c.env as { SITE_URL?: string }),
    // X-Admin-Token intentionally omitted: admin mutations are same-origin
    // only. Exposing it in CORS would let a malicious page on the same
    // domain make cross-origin admin requests if the user has the token
    // in their browser.
    allowHeaders: ['Authorization', 'Content-Type', 'X-API-Key'],
    allowMethods: ['GET', 'POST', 'DELETE', 'PATCH', 'PUT', 'OPTIONS'],
    maxAge: 86400,
  })
);

app.use('/api/v1/*', requestId);
app.use('/api/v1/*', serverTiming);
app.use('/api/v1/*', csrfGuard);
app.use('/api/v1/*', authenticate('external-only'));
// Cheap, route-agnostic input guards (URL/query/body size + JSON shape).
// Runs after auth so we don't pay the parsing cost on rejected requests,
// but before rateLimit/requestLogger so the request logger still sees the
// same request-id and timing. Per-route `validate(...)` middleware still
// runs for typed Zod parsing of the ~15 high-impact POST endpoints.
app.use('/api/v1/*', looseValidation());
// Cache-Control headers for GET responses — static data gets long cache,
// live data gets short or no-cache. Prevents unnecessary re-fetches.
app.use('/api/v1/*', async (c, next) => {
  await next();
  if (c.req.method !== 'GET' || c.res.status !== 200) return;
  const path = new URL(c.req.url).pathname;
  let maxAge = 0;
  let staleWhileRevalidate = 0;
  let staleIfError = 0;
  if (
    path.includes('/si/') ||
    path.includes('/threat-intel/') ||
    path.includes('/ai-security/') ||
    path.includes('/ai-escape/') ||
    path.includes('/frameworks/') ||
    path.includes('/winreg/') ||
    path.includes('/dfir-ref/') ||
    path.includes('/grc/') ||
    path.includes('/siem-library/') ||
    path.includes('/hunt-hypotheses/') ||
    path.includes('/cloud-ref/') ||
    path.includes('/pqc/') ||
    path.includes('/etda-actors/') ||
    path.includes('/tools/') ||
    path.includes('/osint/') ||
    path.includes('/reports/') ||
    path.includes('/campaigns/')
  ) {
    maxAge = 300; // 5 min for static manifest data
    staleWhileRevalidate = 600; // 10 min SWR — serve stale while revalidating
    staleIfError = 86400; // 24h stale-if-error — survive origin blips
  } else if (path.includes('/darknet-intel/') || path.includes('/live-iocs') || path.includes('/ransomware-recent')) {
    maxAge = 60; // 1 min for live data
    staleWhileRevalidate = 30; // 30s SWR for live feeds
    staleIfError = 300; // 5 min on error
  } else if (path.includes('/feed-status') || path.includes('/briefings/')) {
    maxAge = 120; // 2 min for status/briefings
    staleWhileRevalidate = 600; // 10 min SWR
    staleIfError = 3600; // 1h on error
  } else if (path.includes('/profile/gh-stats')) {
    maxAge = 3600; // 1h for README stat cards (self-hosted stats SVGs)
    staleWhileRevalidate = 86400; // 24h SWR
    staleIfError = 86400;
  }
  const headers = new Headers(c.res.headers);
  if (maxAge > 0) {
    const cc = `public, s-maxage=${maxAge}, max-age=${maxAge}, stale-while-revalidate=${staleWhileRevalidate}, stale-if-error=${staleIfError}`;
    headers.set('Cache-Control', cc);
    headers.set('CDN-Cache-Control', cc);
    headers.set('Vary', 'Accept-Encoding');
  } else {
    headers.set('Cache-Control', 'no-store');
  }
  c.res = new Response(c.res.body, { ...c.res, headers });
});
app.use('/api/v1/*', requestLogger);
app.use('/api/v1/*', rateLimit);
// Per-API-key daily/per-minute quota (readonly 1k/day, admin 10k/day), enforced
// in D1 after the cheap per-IP limiter. No-ops for keyless same-origin frontend
// traffic and the internal-agent token (it carries no api-key header), so only
// explicit key holders are metered — closes the "rotate IPs for unlimited
// paid-upstream fan-out" gap the per-IP limiter alone left open.
app.use('/api/v1/*', apiKeyRateLimit);
app.use('/api/v1/*', apiVersion);

// Role gate for mutations, mounted once here rather than per-route.
//
// `requireAdminRole` (lib/auth.ts) only rejects when a caller presents an
// API key whose role is `readonly`; callers with no `c.user` — the same-origin
// SPA, the internal DO token, the OPEN_PUBLIC_READS valve — pass straight
// through. So this cannot break the website's own keyless writes; it only stops
// a readonly key, which is documented as read-only, from reaching a mutation.
//
// Previously this was applied to 5 routes in si-edge-tools.ts out of roughly 180
// mutations, so a readonly key could create and delete SOC playbooks, tamper
// with the estate/risk-register/GRC data, forge compliance evidence, and drive
// the Workers AI spend endpoints. Per-route `requireAdmin(c)` gates (there are
// ~75) still apply and are unaffected.
//
// Deliberately NOT mounted on GET/HEAD: reads are the point of a readonly key.
for (const method of ['POST', 'PUT', 'PATCH', 'DELETE'] as const) {
  app.on(method, '/api/v1/*', requireAdminRole());
}
// Preload the MITRE ATT&CK id index (runtime asset, see lib/attack-id-lazy).
// Memoised per isolate — after the first request this is a pointer read, but
// awaiting here guarantees every downstream handler/lib sees a loaded index
// instead of silently empty lookups. A missing asset fails loudly (500) on
// the first request rather than corrupting lookups all over the API.
app.use('/api/v1/*', async (c, next) => {
  await loadAttackIdIndex(c.env);
  await next();
});
app.use(
  '/api/taxii2/*',
  cors({
    origin: (_, c) => getSiteUrl(c.env as { SITE_URL?: string }),
    allowHeaders: ['Authorization', 'Content-Type', 'X-API-Key'],
    allowMethods: ['GET', 'POST', 'DELETE', 'OPTIONS'],
    maxAge: 86400,
  })
);
app.use('/api/taxii2/*', requestId);
app.use('/api/taxii2/*', csrfGuard);
app.use('/api/taxii2/*', authenticate('external-only'));
app.use('/api/taxii2/*', requestLogger);
app.use('/api/taxii2/*', rateLimit);

// ── Operator-only gates ────────────────────────────────────────────────────
// Sensitive DFIR working data (read AND write — no per-user ownership exists,
// so an open read is a full data dump) and costly AI/paid endpoints require the
// admin token (Authorization: Bearer ADMIN_TOKEN or X-Admin-Token). Registered
// after the global /api/v1/* chain so these run after cors/csrf/auth/ratelimit
// but before the route handler. Header-based "same-origin" trust is NOT an
// authentication grant for these — the admin token is required regardless of
// Origin. The bare path + `/*` cover the collection root and all sub-routes.
const ADMIN_GATED_PREFIXES = [
  '/api/v1/malware-vault',
  '/api/v1/observable-db',
  '/api/v1/investigations',
  '/api/v1/agent',
  '/api/v1/notebooks',
  '/api/v1/threat-intel/assessments',
  '/api/v1/threat-intel/pirs',
  '/api/v1/watches',
  '/api/v1/feed-scheduler',
  '/api/v1/feed-scheduler-history',
  '/api/v1/ct-monitor',
  '/api/v1/dashboard',
  '/api/v1/rag',
  '/api/v1/report',
];
for (const base of ADMIN_GATED_PREFIXES) {
  app.use(base, requireAdminMiddleware);
  app.use(`${base}/*`, requireAdminMiddleware);
}
// Single-path / costly-AI gates. `/api/v1/rules/*` and `/api/v1/yara/*` match
// the generate/validate sub-paths but NOT the public `/api/v1/rules` feed.
app.use('/api/v1/tracer/labels', requireAdminMiddleware);
app.use('/api/v1/graph/ingest', requireAdminMiddleware);
app.use('/api/v1/threat-intel/novelty/batch', requireAdminMiddleware);
app.use('/api/v1/report/parse', requireAdminMiddleware);
app.use('/api/v1/tracer/graphs', requireAdminMiddleware);
app.use('/api/v1/crypto-monitor', requireAdminMiddleware);
app.use('/api/v1/crypto-monitor/*', requireAdminMiddleware);
app.use('/api/v1/tracer/graphs/*', requireAdminMiddleware);
// Public — AI investigation tools use Workers AI (internal billing gate).
// app.use('/api/v1/ai-summary', requireAdminMiddleware);
app.use('/api/v1/yara/*', requireAdminMiddleware);
app.use('/api/v1/rules/generate', requireAdminMiddleware);
app.use('/api/v1/rules/validate', requireAdminMiddleware);
// Admin key-management, cache purge, and retention: gate BEFORE the per-route
// validate() runs so an unauthenticated caller gets a 401 rather than a 400
// that enumerates the request schema (e.g. the key-minting role enum). The
// /api/v1/admin/session login+logout routes are intentionally NOT gated — they
// exchange the admin token in-body for the HttpOnly session cookie.
app.use('/api/v1/admin/keys', requireAdminMiddleware);
app.use('/api/v1/admin/keys/*', requireAdminMiddleware);
app.use('/api/v1/admin/purge', requireAdminMiddleware);
app.use('/api/v1/admin/retention/*', requireAdminMiddleware);
app.use('/api/v1/admin/x-cookies', requireAdminMiddleware);
app.use('/api/v1/admin/x-qids', requireAdminMiddleware);
// Telegram bot-status leaks the operator's private monitored-channel map and
// bot/poll triggers upstream fan-out + KV writes — both operator-only. These
// two registrations sit BEFORE the case-study sub-app's catch-all admin gate,
// so they need their own explicit gate (Hono does not retroactively wrap
// earlier-registered handlers).
app.use('/api/v1/admin/telegram', requireAdminMiddleware);
app.use('/api/v1/admin/telegram/*', requireAdminMiddleware);
// maltrail-sync writes KV-backed actor records and fans out to the GitHub API;
// it is an operator-only mutation, not a public/readonly-key endpoint.
app.use('/api/v1/maltrail-sync', requireAdminMiddleware);
// CTI operator pipelines — global-table writes (collect/mutate/decay/sweep)
// plus AI prediction cost, with a caller-controlled wipe cutoff on sweep.
// Cron calls the lib functions directly and no SPA/MCP/SELF path hits these
// handlers, so gating the HTTP layer is cron-safe.
app.use('/api/v1/cti/collect', requireAdminMiddleware);
app.use('/api/v1/cti/predictions', requireAdminMiddleware);
app.use('/api/v1/cti/mutate', requireAdminMiddleware);
app.use('/api/v1/cti/decay', requireAdminMiddleware);
app.use('/api/v1/cti/sweep', requireAdminMiddleware);

import {
  iocCheckSchema,
  domainLookupSchema,
  intodnsSnapshotSchema,
  intodnsExplainSchema,
  intodnsDomainSchema,
  ipGeoSchema,
  cveLookupSchema,
  mitreTechniqueSchema,
  searchSchema,
  waybackSchema,
  googleDorksSchema,
  cryptoTraceSchema,
  tracerExpandSchema,
  tracerLabelSchema,
  tracerLabelAddSchema,
  tracerCalldataSchema,
  tracerGraphSaveSchema,
  cryptoWatchAddSchema,
  ctCertsSchema,
  iocLifecycleSchema,
  iocTrendingSchema,
  relationshipGraphSchema,
  unifiedSearchSchema,
  ragQuerySchema,
  hashAnalyzeSchema,
  bloomCheckSchema,
  osvScanSchema,
  depsDevPackageSchema,
  telegramChannelActionSchema,
  telegramBotRegisterSchema,
  aiSummarySchema,
  aiItemSummarySchema,
  copilotInvestigateSchema,
  reportBuildSchema,
  huntingQuerySchema,
  irPlaybookSchema,
  ruleGenerateSchema,
  ruleValidateSchema,
  fplensAnalyzeSchema,
  threatIntelFeedbackSchema,
  assessmentSchema,
  assessmentUpdateSchema,
  pirCreateSchema,
  pirUpdateSchema,
  pirAlertAckSchema,
  investigationCreateSchema,
  investigationUpdateSchema,
  investigationObservableSchema,
  investigationTaskSchema,
  investigationTaskUpdateSchema,
  investigationNoteSchema,
  feedJobCreateSchema,
  feedJobUpdateSchema,
  observableCreateSchema,
  observableUpdateSchema,
  observableNoteSchema,
  watchCreateSchema,
  watchUpdateSchema,
  campaignCreateSchema,
  watchlistUpdateSchema,
  intelBundleBuildSchema,
  predictiveAttributionSchema,
  attackChainReconstructSchema,
  actorDnaMatchSchema,
  correlationSchema,
  noveltyBatchSchema,
  campaignAnalyzeSchema,
  threatIntelEntityExtractSchema,
  threatIntelEntityProfileSchema,
  achGenerateSchema,
  domainSnapshotSchema,
  openDirScanSchema,
  graphIngestSchema,
  mispProxySchema,
  actorEnrichStreamSchema,
  campaignGeneratorSchema,
  automationRunSchema,
  agentInvestigateSchema,
  briefingBuildSchema,
  briefingBackfillSchema,
  briefingDeleteSchema,
  ragIndexSchema,
  adminPurgeSchema,
  adminRetentionSchema,
  adminApiKeyCreateSchema,
  phishingEmailTextSchema,
  stixBundleTextSchema,
  exploitDbSchema,
  cisaKevSchema,
  certInSchema,
  supplyChainAttacksSchema,
  k8sCveSchema,
  mispGalaxyActorsSchema,
  cloudThreatLandscapeSchema,
  ransomwhereSchema,
  disarmFrameworkSchema,
  attackFlowLibrarySchema,
  volexityThreatIntelSchema,
  securityUpdatesSchema,
  passiveDnsSchema,
  githubSecuritySchema,
  waybackAdvancedSchema,
} from './lib/validation-schemas';

// ── Health Checks ──────────────────────────────────────────────────

import { apiVersion } from './lib/api-version';
import {
  exportStixHandler,
  exportMispHandler,
  exportSigmaHandler,
  exportYaraHandler,
  exportSnortHandler,
  exportSuricataHandler,
  exportCsvHandler,
  exportPfSenseHandler,
} from './routes/export';
import {
  siIndexHandler,
  siSkillsHandler,
  siSkillHandler,
  siQueriesHandler,
  siQueryHandler,
  siQueryBySlugHandler,
  siAutomationsHandler,
  siAutomationHandler,
  siDocsHandler,
  siDocHandler,
  siRefListHandler,
  siRefHandler,
  siRoutingPromptHandler,
  siScriptsHandler,
  siScriptHandler,
  siRenderHandler,
} from './routes/security-investigator';
import { siEdgeToolsRouter } from './routes/si-edge-tools';
import { threatIntelRouter } from './routes/threat-intel-edge-tools';
import { dailyBriefsRouter } from './routes/daily-briefs-edge-tools';
import { webamonDtbRouter } from './routes/webamon-dtb';
import { aiThreatsRouter } from './routes/ai-threats-edge-tools';
import { aiEscapeRouter } from './routes/ai-escape';
import { aiSecurityRouter } from './routes/ai-security';
import { ransomwareGroupsRouter } from './routes/ransomware-groups';
import { anarchyRouter } from './routes/anarchy';
import { ossFeedsRouter } from './routes/oss-feeds-edge-tools';
import { winRegRouter } from './routes/winreg-edge-tools';
import { pcmedicalistRouter } from './routes/pcmedicalist';
import { sigBaseRouter } from './routes/sigbase-edge-tools';
import { breachWatchRouter } from './routes/breach-watch-edge-tools';
import { osintRouter } from './routes/osint-edge-tools';
import { ctiBookmarksRouter } from './routes/cti-bookmarks-edge-tools';
import { lotsRouter } from './routes/lots-edge-tools';
import { malapiRouter } from './routes/malapi-edge-tools';
import { carRouter } from './routes/car-edge-tools';
import { capecRouter } from './routes/capec-edge-tools';
import { hijacklibsRouter } from './routes/hijacklibs-edge-tools';
import { verisRouter } from './routes/veris-edge-tools';
import { engageRouter } from './routes/engage-edge-tools';
import { cairnRouter } from './routes/cairn-edge-tools';
import { novaRouter } from './routes/nova-edge-tools';
import { denaliRouter } from './routes/denali-edge-tools';
import { aiPlaybookRouter } from './routes/ai-playbook-edge-tools';
import { reportsRouter } from './routes/reports-edge-tools';
import { campaignsRouter } from './routes/campaigns-edge-tools';
import { traceixRouter } from './routes/traceix';
import { profileStatsRouter } from './routes/profile-stats';
import { nhiScanRouter } from './routes/nhi-scan';
import { whoxyRouter } from './routes/whoxy';
import { heatwaveLookupHandler } from './routes/heatwave';
import { threatMonitorRouter } from './routes/threat-monitor';
import { truecallerRouter } from './routes/truecaller';
import { fullhuntRouter } from './routes/fullhunt';
import { opensanctionsRouter } from './routes/opensanctions';
import { cloakRouter } from './routes/cloak-edge-tools';
import { dehashRouter } from './routes/dehash';
import { opencveRouter } from './routes/opencve';
import { darknetIntelRouter } from './routes/darknet-intel-tools';
import { darkwebOsintRouter } from './routes/darkweb-osint';
import { fbiWantedRouter } from './routes/fbi-wanted';
import { interpolRouter } from './routes/interpol';
import { mozillaTlsRouter } from './routes/mozilla-tls';
import { virusheeRouter } from './routes/virushee';
import { toolsRouter } from './routes/tools-edge-tools';
import { etdaActorsRouter } from './routes/etda-actors-edge-tools';
import { dfirRefRouter } from './routes/dfir-ref-edge-tools';
import { grcRouter } from './routes/grc-edge-tools';
import { siemLibraryRouter } from './routes/siem-library-edge-tools';
import { huntHypothesesRouter } from './routes/hunt-hypotheses-edge-tools';
import { observableExtractRouter } from './routes/observable-extract';
import { fileTriageRouter } from './routes/file-triage';
import { ruleValidatorRouter } from './routes/rule-validator';
import { netAnalyticsRouter } from './routes/net-analytics-tools';
import { velociraptorRouter } from './routes/velociraptor';
import { sampleSubmissionRouter } from './routes/sample-submission';
import { cloudRefRouter } from './routes/cloud-ref-edge-tools';
import { pqcRouter } from './routes/pqc-edge-tools';
import { detectionWikiRouter } from './routes/detection-wiki-edge-tools';
import { flowvizRouter } from './routes/flowviz';
import { proceduresRouter } from './routes/procedures';
import {
  listNotebooksHandler,
  getNotebookHandler,
  createNotebookHandler,
  updateNotebookHandler,
  deleteNotebookHandler,
  addEntryHandler,
  updateEntryHandler,
  deleteEntryHandler,
  notebookStatsHandler,
} from './routes/notebooks';
import { estateRoutes } from './routes/estate';

import {
  listWorkspacesHandler,
  createWorkspaceHandler,
  getWorkspaceHandler,
  updateWorkspaceHandler,
  deleteWorkspaceHandler,
  listSubjectsHandler,
  createSubjectHandler,
  listConnectionsHandler,
  createConnectionHandler,
  listFindingsHandler,
  createFindingHandler,
  listTimelineHandler,
  addTimelineHandler,
  exposureScoreHandler,
  exportStixCtiHandler,
  renderGraphHandler,
  workflowStateHandler,
  workflowAdvanceHandler,
  workflowSummaryHandler,
  exportWorkspaceHandler,
} from './routes/cti-workspaces';

import healthRoutes from './routes/health';
app.route('/', healthRoutes);

app.get('/api/v1/ioc/enrich-deep', iocEnrichDeepHandler);
app.post('/api/v1/ioc/enrich-deep', iocEnrichDeepHandler);
app.get('/api/v1/ioc/check', validate('query', iocCheckSchema), iocCheckHandler);
app.get('/api/v1/domain/lookup', validate('query', domainLookupSchema), domainLookupHandler);
app.get('/api/v1/intodns/snapshot', validate('query', intodnsSnapshotSchema), intodnsSnapshotHandler);
app.get('/api/v1/intodns/explain', validate('query', intodnsExplainSchema), intodnsExplainHandler);
app.get('/api/v1/intodns/blacklist', validate('query', intodnsDomainSchema), intodnsBlacklistHandler);
app.get(
  '/api/v1/intodns/sender-requirements',
  validate('query', intodnsDomainSchema),
  intodnsSenderRequirementsHandler
);
app.get('/api/v1/intodns/smtp-tls', validate('query', intodnsDomainSchema), intodnsSmtpTlsHandler);
app.get('/api/v1/intodns/fcrdns', validate('query', intodnsDomainSchema), intodnsFcrdnsHandler);
app.get('/api/v1/intodns/dnssec', validate('query', intodnsDomainSchema), intodnsDnssecHandler);
app.get('/api/v1/intodns/sec-headers', validate('query', intodnsDomainSchema), intodnsSecHeadersHandler);
app.get('/api/v1/intodns/badge', validate('query', intodnsDomainSchema), intodnsBadgeHandler);
app.post('/api/v1/intodns/debug-email', intodnsDebugEmailHandler);
app.post(
  '/api/v1/phishing/analyze',
  validateText(phishingEmailTextSchema, { maxBytes: 64 * 1024 }),
  phishingAnalyzeHandler
);
// URL risk analyzer — IntelX-style weighted 5-source correlation
// (VirusTotal / Google Safe Browsing / URLScan / AbuseIPDB / WHOIS age).
app.post('/api/v1/url-risk/analyze', urlRiskAnalyzeHandler);
app.post('/api/v1/file/analyze', validate('json', hashAnalyzeSchema), fileAnalyzeHandler);
app.get('/api/v1/feeds/proxy', feedProxyHandler);
app.get('/api/v1/feeds/abuse-rss', abuseRssHandler);
// /threatsignal — live RSS proxy + parsed JSON for the /threatintel/threatsignal page.
// Public (no auth): the feed is a public research publication and we want the
// page to hydrate without an admin token.
app.get('/api/v1/threatsignal/rss', threatSignalRssHandler);
app.get('/api/v1/threatsignal/rss.xml', threatSignalRssXmlHandler);
// /opensourcemalware — second source, same shape, separate cache key.
app.get('/api/v1/opensourcemalware/rss', openSourceMalwareRssHandler);
app.get('/api/v1/opensourcemalware/rss.xml', openSourceMalwareRssXmlHandler);
// /rss/aggregate — merged feed across all sources (or one source via ?source=).
// Powers the /threatintel/threatsignal page. Returns 207 (Multi-Status) if
// some sources are unreachable but at least one is healthy.
app.get('/api/v1/rss/aggregate', rssAggregateHandler);
// /rss/sources — light endpoint for clients that want to render their own
// source picker without hard-coding ids.
app.get('/api/v1/rss/sources', rssSourcesHandler);
app.get('/api/v1/feeds/mti-ransomware', mtiRansomwareRssHandler);
app.get('/api/v1/feeds/ransomware-merged', ransomwareMergedRssHandler);
app.get('/api/v1/feeds/ioc-summary', iocFeedSummaryHandler);
app.post('/api/v1/cti/parse', validateText(stixBundleTextSchema, { maxBytes: 1024 * 1024 }), ctiParseHandler);
app.post('/api/v1/osv/scan', validate('json', osvScanSchema), osvScanHandler);
app.get('/api/v1/privacy/inspect', privacyInspectHandler);
app.get('/api/v1/cve/lookup', validate('query', cveLookupSchema), cveSearchHandler);
app.get('/api/v1/cve/search', validate('query', cveLookupSchema), cveSearchHandler);
app.post('/api/v1/cve/lookup/batch', cveBatchLookupHandler);
app.get('/api/v1/mitre/technique', validate('query', mitreTechniqueSchema), mitreTechniqueHandler);
app.get('/api/v1/atlas/technique', atlasTechniqueHandler);
app.get('/api/v1/asn/lookup', asnLookupHandler);
app.get('/api/v1/breach/range', breachRangeHandler);
app.get('/api/v1/breach/email', breachEmailHandler);
app.get('/api/v1/breach/domain', breachDomainHandler);
app.get('/api/v1/breach/leakix', leakIxSearchHandler);
app.get('/api/v1/breach/proxynova', proxyNovaSearchHandler);

// ── TI-Mindmap-Hub MCP proxy (CORS relay) ──────────────────────────
// The upstream MCP server (mcp.ti-mindmap-hub.com) does not send CORS
// headers, so a browser cross-origin POST fails the preflight. This
// proxy terminates the request on our origin, replays it to the
// upstream with the user's X-API-Key (forwarded in the body), and
// relays the response back. The key is never persisted server-side.
app.options('/api/v1/mcp/proxy', mcpProxyOptions);
app.post('/api/v1/mcp/proxy', mcpProxyHandler);
app.get('/api/v1/breach/hudsonrock', hudsonRockSearchHandler);
app.get('/api/v1/breach/hudsonrock/domain', hudsonRockDomainHandler);
app.get('/api/v1/hudsonrock/domain-overview', hudsonRockDomainOverviewHandler);
app.get('/api/v1/hudsonrock/discovery', hudsonRockDiscoveryHandler);
app.get('/api/v1/hudsonrock/assessment', hudsonRockAssessmentHandler);
app.get('/api/v1/hudsonrock/infection-analysis', hudsonRockInfectionAnalysisHandler);
app.get('/api/v1/hudsonrock/username', hudsonRockUsernameHandler);
app.get('/api/v1/hudsonrock/ip', hudsonRockIpHandler);
app.get('/api/v1/hudsonrock/account', hudsonRockAccountHandler);
app.get('/api/v1/breach/projectdiscovery', projectDiscoveryHandler);
app.get('/api/v1/pd/leaks', pdLeaksHandler);
app.get('/api/v1/pd/subdomains', pdSubdomainsHandler);
app.get('/api/v1/pd/cves', pdCvesHandler);
app.get('/api/v1/pd/cve-detail', pdCveDetailHandler);
app.get('/api/v1/abuse-rep', stopForumSpamHandler);
app.get('/api/v1/urlscan-ip', urlscanIpHandler);
app.get('/api/v1/breach/hackmyip', hackMyIpBreachHandler);
app.get('/api/v1/identity/lookup', identityProxyHandler);
app.get('/api/v1/url-preview', urlPreviewHandler);
app.get('/api/v1/takeover/check', takeoverCheckHandler);
app.get('/api/v1/threat-map', threatMapHandler);
app.get('/api/v1/feeds/aggregate', feedsAggregateHandler);
app.get('/api/v1/rules', detectionRulesHandler);
app.get('/api/v1/orkl/search', orklSearchHandler);
app.get('/api/v1/orkl/entry/:uuid', orklEntryHandler);
app.get('/api/v1/orkl/info', orklInfoHandler);
app.get('/api/v1/deepdarkcti', deepDarkCtiHandler);
app.get('/api/v1/stealer-forum-intel', stealerForumIntelHandler);
app.get('/api/v1/secret-leaks', secretLeaksHandler);
app.get('/api/v1/attack-navigator', attackNavigatorHandler);
app.get('/api/v1/a3m-matrix', a3mMatrixHandler);
app.get('/api/v1/d3fend-matrix', d3fendMatrixHandler);
app.get('/api/v1/breach-forums', breachForumsHandler);
app.get('/api/v1/breach-forum-status/deltas', breachForumStatusHandler);
app.get('/api/v1/breach-coverage', breachCoverageHandler);
app.get('/api/v1/negotiations', negotiationsHandler);
app.get('/api/v1/negotiations/:group/:id', negotiationTranscriptHandler);
app.get('/api/v1/rl/kql', kqlIndexHandler);
app.get('/api/v1/rl/kql/:id', kqlViewHandler);
app.get('/api/v1/rl/:resource', ransomwareLiveHandler);
app.get('/api/v1/rl/:resource/:arg', ransomwareLiveHandler);
app.get('/api/v1/breach-disclosures', breachDisclosuresHandler);
// CyberPulse — breach/leak incident tracker (social media firehose)
app.get('/api/v1/cyberpulse/incidents', cyberpulseIncidentsHandler);
app.get('/api/v1/cyberpulse/stats', cyberpulseStatsHandler);
app.get('/api/v1/cyberpulse/trending', cyberpulseTrendingHandler);
app.get('/api/v1/cyberpulse/scan-log', cyberpulseScanLogHandler);
app.get('/api/v1/cyberpulse/ingest', cyberpulseIngestHandler);
// Registered here, not next to the `rateLimit` mount above, so it sits after
// the global `authenticate('external-only')` chain. See the note by the
// rateLimit mount at the top of this block for why that matters.
app.post('/api/v1/cyberpulse/scan', cyberpulseScanHandler);
app.get('/api/v1/ransomware-recent', ransomwareRecentHandler);
app.get('/api/v1/ransomware-map', ransomwareMapHandler);
app.get('/api/v1/crypto-trace', validate('query', cryptoTraceSchema), cryptoTraceHandler);
app.get('/api/v1/darknet/tor-status', torStatusHandler);
app.get('/api/v1/darknet/tor-fetch-onion', torFetchOnionHandler);
app.get('/api/v1/darknet/tor-scrape-onion', torScrapeOnionHandler);
app.get('/api/v1/darknet/tor-search-onion', torSearchOnionHandler);
app.get('/api/v1/darknet/tor-exit-nodes', torExitNodesHandler);
app.get('/api/v1/darknet/tor-exit-check', torExitCheckHandler);
app.get('/api/v1/darknet/tor-exit-details', torExitDetailsHandler);
app.get('/api/v1/darknet/onion-lookup', onionLookupHandler);
app.get('/api/v1/darknet/btc-abuse-check', btcAbuseCheckHandler);
app.get('/api/v1/supply-chain/package', validate('query', depsDevPackageSchema), depsDevPackageHandler);
app.post('/api/v1/tracer/expand', validate('json', tracerExpandSchema), tracerExpandHandler);
app.get('/api/v1/tracer/label', validate('query', tracerLabelSchema), tracerLabelHandler);
app.post('/api/v1/tracer/labels', validate('json', tracerLabelAddSchema), tracerLabelAddHandler);
app.get('/api/v1/tracer/calldata', validate('query', tracerCalldataSchema), tracerCalldataHandler);
app.post('/api/v1/tracer/graphs', validate('json', tracerGraphSaveSchema), tracerGraphSaveHandler);
app.get('/api/v1/tracer/graphs', tracerGraphListHandler);
app.get('/api/v1/tracer/graphs/:id', tracerGraphGetHandler);
app.delete('/api/v1/tracer/graphs/:id', tracerGraphDeleteHandler);
app.post('/api/v1/crypto-monitor/watch', validate('json', cryptoWatchAddSchema), cryptoWatchAddHandler);
app.get('/api/v1/crypto-monitor/watches', cryptoWatchListHandler);
app.delete('/api/v1/crypto-monitor/watch/:address/:chain', cryptoWatchRemoveHandler);
app.get('/api/v1/crypto-monitor/alerts', cryptoAlertsHandler);
app.get('/api/v1/wayback/cdx', validate('query', waybackSchema), waybackCdxHandler);
app.get('/api/v1/threat-pulse', threatPulseHandler);
app.get('/api/v1/firms-ukmto', firmsUkmtoHandler);
// Split routes for global-pulse handler (expects separate endpoints)
app.get('/api/v1/firms-fires', async (c) => {
  const res = await firmsUkmtoHandler(c);
  if (!res.ok) return res;
  const data = (await res.json()) as { fires: unknown[] };
  return c.json({ fires: data.fires ?? [] });
});
app.get('/api/v1/ukmto-incidents', async (c) => {
  const res = await firmsUkmtoHandler(c);
  if (!res.ok) return res;
  const data = (await res.json()) as { incidents: unknown[] };
  return c.json({ incidents: data.incidents ?? [] });
});
app.get('/api/v1/ip-geo', validate('query', ipGeoSchema), ipGeoHandler);
app.get('/api/v1/stix/fetch', stixFetchHandler);
app.get('/api/v1/cert-search', certSearchHandler);
app.get('/api/v1/web-scan', webScanHandler);
app.get('/api/v1/exposure/scan', exposureScanHandler);
app.get('/api/v1/exposure/check', exposureCheckHandler);
app.get('/api/v1/host', hostIntelHandler);
app.get('/api/v1/onion-watch', onionWatchHandler);
app.get('/api/v1/builtwith', builtwithHandler);
app.get('/api/v1/ct-log', ctLogHandler);
app.get('/api/v1/wayback/advanced', validate('query', waybackAdvancedSchema), waybackAdvancedHandler);
app.get('/api/v1/telegram-feed', telegramFeedHandler);
app.get('/api/v1/tg-live-search', tgLiveSearchHandler);
app.get('/api/v1/telegram-search', telegramSearchHandler);
app.get('/api/v1/telegram-channel-meta', telegramChannelMetaHandler);
app.get('/api/v1/telegram-custom-channels', telegramCustomChannelsGetHandler);
app.post(
  '/api/v1/telegram-custom-channels',
  validate('json', telegramCustomChannelSchema),
  telegramCustomChannelsPostHandler
);
app.delete('/api/v1/telegram-custom-channels/:handle', telegramCustomChannelsDeleteHandler);
app.get('/api/v1/admin/telegram/bot-status', telegramBotStatusHandler);
app.post('/api/v1/admin/telegram/bot/register', telegramBotRegisterHandler);
app.post('/api/v1/admin/telegram/bot/poll', async (c) => {
  const result = await pollBotUpdatesWithResult(c.env);
  return c.json(result);
});
app.get('/api/v1/telegram-bot/status', async (c) => {
  const env = c.env as unknown as Record<string, unknown>;
  const token = env.TELEGRAM_BOT_TOKEN as string | undefined;
  const kv = env.KV_CACHE as import('@cloudflare/workers-types').KVNamespace | undefined;
  const configured = !!token;
  let botUsername: string | null = null;
  if (token) {
    try {
      const r = await fetch(`https://api.telegram.org/bot${token}/getMe`);
      if (r.ok) {
        const data = (await r.json()) as { ok: boolean; result?: { username?: string } };
        botUsername = data?.result?.username ?? null;
      }
    } catch {
      /* swallow */
    }
  }
  let cachedChannels: string[] = [];
  if (kv) {
    try {
      const raw = await kv.get('tg:bot-channel-map');
      if (raw) cachedChannels = Object.keys(JSON.parse(raw));
    } catch {
      /* swallow */
    }
  }
  return c.json({ configured, bot_username: botUsername, cached_channels: cachedChannels });
});

// ── Telegram Leak Monitor (Tier 1: t.me scraping) ─────────────────────────
app.get('/api/v1/telegram-leaks/search', telegramLeakSearchHandler);
app.get('/api/v1/telegram-leaks/discovered-channels', telegramDiscoveredChannelsHandler);
app.get('/api/v1/telegram-leaks/watched-channels', telegramWatchedChannelsHandler);
app.get('/api/v1/telegram-leaks/stats', telegramLeakStatsHandler);
app.get('/api/v1/telegram-leaks/geo', telegramLeakGeoHandler);
app.post(
  '/api/v1/telegram-leaks/approve-channel',
  validate('json', telegramChannelActionSchema),
  telegramApproveChannelHandler
);
app.post(
  '/api/v1/telegram-leaks/reject-channel',
  validate('json', telegramChannelActionSchema),
  telegramRejectChannelHandler
);

// ── Telegram Leak Monitor (Tier 2: Bot API) ──────────────────────────────
app.get('/api/v1/telegram-leaks/bot-webhook-status', telegramLeakBotWebhookStatusHandler);
app.post('/api/v1/telegram-leaks/bot-webhook', telegramLeakBotWebhookHandler);
app.post(
  '/api/v1/telegram-leaks/register-webhook',
  validate('query', telegramBotRegisterSchema),
  telegramLeakBotRegisterHandler
);

app.get('/api/v1/webamon/search', webamonSearchHandler);
app.post('/api/v1/webamon/scan', webamonScanHandler);
app.get('/api/v1/webamon/reports', webamonReportsHandler);
app.get('/api/v1/webamon/report/:id', webamonReportHandler);
app.get('/api/v1/webamon/screenshot/:id', webamonScreenshotHandler);
app.get('/api/v1/webamon/domain/:name', webamonDomainHandler);
app.get('/api/v1/webamon/server/:ip', webamonServerHandler);
app.get('/api/v1/webamon/resource/:sha256', webamonResourceHandler);
app.get('/api/v1/webamon/campaigns/stats', webamonCampaignStatsHandler);
app.get('/api/v1/webamon/campaigns/:id/domains', webamonCampaignDomainsHandler);
app.get('/api/v1/webamon/campaigns', webamonCampaignsHandler);
app.get('/api/v1/webamon/changes', webamonChangesHandler);
app.get('/api/v1/webamon/clusters', webamonClustersHandler);
app.get('/api/v1/webamon/campaign-intel', webamonCampaignIntelHandler);
app.get('/api/v1/global-pulse', globalPulseHandler);
app.get('/api/v1/live-feed/export', liveFeedExportHandler);
app.post('/api/v1/threat-analysis', threatAnalysisHandler);
app.post('/api/v1/ioc-extraction', iocExtractionHandler);
app.post('/api/v1/mitre-mapping', mitreMappingHandler);
app.post('/api/v1/country-intel', countryIntelHandler);
app.post('/api/v1/event-correlation', eventCorrelationHandler);
app.post('/api/v1/campaign-tracker', campaignTrackerHandler);
app.post('/api/v1/feed-quality', assessFeedQualityHandler);
app.post('/api/v1/story-cluster', storyClusterHandler);
app.post('/api/v1/alert-check', alertCheckHandler);
app.post('/api/v1/research-digest', researchDigestHandler);
app.post('/api/v1/darkweb-intel', darkwebIntelHandler);
app.post('/api/v1/knowledge-graph', knowledgeGraphHandler);
app.get('/api/v1/cve-recent', cveRecentHandler);
// Daily CVE digest — every CVE published in the last 24h. Separate route (and
// cache key) from cve-recent because the promise is different: cve-recent is a
// recent SAMPLE bounded by NVD paging, this is a complete window. Cron-warmed,
// same edge-cache → KV-last-good → 503 discipline.
app.get('/api/v1/cve-digest', cveDigestHandler);
// Same warmed payload, alternate representations — CSV for spreadsheets and
// RSS for readers. Both derive from the cached JSON (never rebuild), each
// with its own edge-cache key.
app.get('/api/v1/cve-digest/csv', cveDigestCsvHandler);
// The RSS path is NOT in auth.ts EXEMPT_PATHS: it is unlocked by a signed,
// path-scoped `?key=` feed token instead, so it works in any reader without
// being world-enumerable. This endpoint mints that URL and sits behind the
// normal API gate — it is the only place a token is handed out.
app.get('/api/v1/cve-digest/rss', cveDigestRssHandler);
app.get('/api/v1/cve-digest/feed-url', cveDigestFeedUrlHandler);
// PromptIntel IoPC registry (NovaHunting) — cached taxonomy/health + live
// keyed prompt search. Keyed handlers degrade to 501 without the secret.
app.get('/api/v1/promptintel/health', promptintelHealthHandler);
app.get('/api/v1/promptintel/taxonomy', promptintelTaxonomyHandler);
app.get('/api/v1/promptintel/taxonomy/entries/:id', promptintelEntryHandler);
app.get('/api/v1/promptintel/prompts', promptintelPromptsHandler);
app.get('/api/v1/cve-threat-map', cveThreatMapHandler);
app.get('/api/v1/cve-poc-scan', cvePocScanHandler);
app.get('/api/v1/cve-poc-map', cvePocMapHandler);
app.get('/api/v1/cyber-news', cyberNewsHandler);
app.get('/api/v1/cve-health', cveHealthHandler);
app.post('/api/v1/soc-cve-report', socCveReportHandler);
app.post('/api/v1/soc-cve-report/json', socCveReportJsonHandler);
app.get('/api/v1/phishing-urls', phishingUrlsHandler);
app.get('/api/v1/crypto-scam-feed', cryptoScamFeedHandler);
app.get('/api/v1/actor-usernames', actorUsernamesHandler);
app.get('/api/v1/actor-usernames/stats', actorUsernamesStatsHandler);
app.get('/api/v1/username-osint', usernameOsnitHandler);
app.get('/api/v1/username-osint/patterns', usernamePatternsHandler);
app.get('/api/v1/username-osint/profile', usernameProfileHandler);
app.get('/api/v1/phone-osint', phoneOsintHandler);
app.get('/api/v1/opensourcemalware/check', osmCheckHandler);
app.get('/api/v1/opensourcemalware/latest', osmLatestHandler);
app.get('/api/v1/reverse-image-search', reverseImageSearchHandler);
app.get('/api/v1/wifi-investigation', wifiInvestigationHandler);
// Live forum-handle search via threatactorusernames.com (ScrapedIntel). Cache +
// global egress budget + last-good live in the lookup layer; manual 2–80 char gate.
app.get('/api/v1/scrapedintel-usernames', scrapedintelUsernamesHandler);
app.get('/api/v1/phishing-wordlists', phishingWordlistsHandler);
app.get('/api/v1/malware-samples', malwareSamplesHandler);
app.get('/api/v1/malware-capabilities', malwareCapabilitiesHandler);
app.post('/api/v1/infra-search', infraSearchHandler);
app.get('/api/v1/infra-search', infraSearchHandler);
app.get('/api/v1/reddit-feed', redditFeedHandler);
app.get('/api/v1/x-feed', xFeedHandler);
app.get('/api/v1/ai-honeypot-feed', aiHoneypotFeedHandler);
app.get('/api/v1/feed-status', feedStatusHandler);
app.get('/api/v1/feed-quality', tifceFeedQualityHandler);
app.get('/api/v1/agent/debug-llm', agentDebugLlmHandler);
app.post('/api/v1/agent/investigate', validate('json', agentInvestigateSchema), agentInvestigateHandler);
app.delete('/api/v1/agent/:id', agentDeleteHandler);
app.get('/api/v1/agent/sessions', agentSessionsHandler);
app.get('/api/v1/agent/metrics', agentMetricsHandler);
app.get('/api/v1/agent/provider-health', agentProviderHealthHandler);
app.get('/api/v1/agent/memory', agentMemoryHandler);
app.get('/api/v1/agent/knowledge-graph', agentKnowledgeGraphHandler);
app.get('/api/v1/agent/history', agentHistoryHandler);
app.get('/api/v1/agent/:id/stream', agentStreamHandler);
app.get('/api/v1/agent/:id', agentStateHandler);
app.post('/api/v1/tie/enrich', tieEnrichHandler);
app.get('/api/v1/tie/enrich/:id', tieEnrichStateHandler);
app.get('/api/v1/tie/enrich/:id/stream', tieEnrichStreamHandler);
app.get('/api/v1/ioc-correlation', iocCorrelationHandler);
app.post('/api/v1/ioc/explain', iocExplainHandler);
app.post('/api/v1/ioc/rule', iocRuleHandler);
app.get('/api/v1/actor-timeline', actorTimelineHandler);
app.get('/api/v1/victim-releaks', victimReleaksHandler);
app.get('/api/v1/live-iocs', liveIocsHandler);
app.get('/api/v1/ai-llm-intel', aiLlmIntelHandler);
app.get('/api/v1/detections', detectionsHandler);
app.get('/api/v1/mti', mtiHandler);
app.get('/api/v1/mti-dns', mtiDnsHandler);
app.get('/api/v1/writeups', writeupsHandler);
app.get('/api/v1/c2-tracker', c2TrackerHandler);
app.get('/api/v1/aggregated-feeds', aggregatedFeedsHandler);
app.get('/api/v1/malware-iocs', malwareFamilyListHandler);
app.get('/api/v1/malware-iocs/:family', malwareFamilyDetailHandler);
app.get('/api/v1/feed-catalog', feedCatalogHandler);
app.get('/api/v1/yara-hub', yaraHubListHandler);
app.get('/api/v1/yara-hub/rule/:uuid', yaraHubRuleHandler);
app.get('/api/v1/investigations', listInvestigationsHandler);
app.post('/api/v1/investigations', validate('json', investigationCreateSchema), createInvestigationHandler);
app.get('/api/v1/investigations/:id', getInvestigationHandler);
app.patch('/api/v1/investigations/:id', validate('json', investigationUpdateSchema), updateInvestigationHandler);
app.delete('/api/v1/investigations/:id', deleteInvestigationHandler);
app.post(
  '/api/v1/investigations/:id/observables',
  validate('json', investigationObservableSchema),
  addObservableHandler
);
app.delete('/api/v1/investigations/:id/observables/:observableId', removeObservableHandler);
app.post('/api/v1/investigations/:id/tasks', validate('json', investigationTaskSchema), addTaskHandler);
app.patch(
  '/api/v1/investigations/:id/tasks/:taskId',
  validate('json', investigationTaskUpdateSchema),
  updateTaskHandler
);
app.post('/api/v1/investigations/:id/notes', validate('json', investigationNoteSchema), addNoteHandler);
app.get('/api/v1/feed-scheduler', listFeedJobsHandler);
app.post('/api/v1/feed-scheduler', validate('json', feedJobCreateSchema), createFeedJobHandler);
app.patch('/api/v1/feed-scheduler/:id', validate('json', feedJobUpdateSchema), updateFeedJobHandler);
app.delete('/api/v1/feed-scheduler/:id', deleteFeedJobHandler);
app.post('/api/v1/feed-scheduler/:id/run', runFeedJobHandler);
app.get('/api/v1/feed-scheduler/:id/history', getFeedJobHistoryHandler);
app.get('/api/v1/feed-scheduler-history', getFeedJobsHistoryAllHandler);
app.get('/api/v1/observable-db', listObservablesHandler);
app.get('/api/v1/observable-db/tags', getObservableTagsHandler);
app.get('/api/v1/observable-db/:id', getObservableHandler);
app.post('/api/v1/observable-db', validate('json', observableCreateSchema), saveObservableHandler);
app.patch('/api/v1/observable-db/:id', validate('json', observableUpdateSchema), updateObservableHandler);
app.delete('/api/v1/observable-db/:id', deleteObservableHandler);
app.post('/api/v1/observable-db/:id/notes', validate('json', observableNoteSchema), addObservableNoteHandler);
app.delete('/api/v1/observable-db/:id/notes/:noteId', deleteObservableNoteHandler);
app.get('/api/v1/malware-vault', listVaultSamplesHandler);
app.get('/api/v1/malware-vault/families', getVaultFamiliesHandler);
app.get('/api/v1/malware-vault/tags', getVaultTagsHandler);
app.get('/api/v1/malware-vault/:id', getVaultSampleHandler);
app.post('/api/v1/malware-vault', uploadVaultSampleHandler);
app.patch('/api/v1/malware-vault/:id', updateVaultSampleHandler);
app.delete('/api/v1/malware-vault/:id', deleteVaultSampleHandler);
app.get('/api/v1/malware-vault/:id/download', downloadVaultSampleHandler);
app.get('/api/v1/intel-bundle', intelBundleHandler);
app.post('/api/v1/intel-bundle', intelBundlePostHandler);
app.post('/api/v1/intel-bundle/build', validate('json', intelBundleBuildSchema), intelBundleBuildHandler);
app.get('/api/v1/intel-bundle/by-id/:bundleId', intelBundleByIdHandler);
app.get('/api/v1/intel-bundle/:id/export.stix.json', intelBundleExportHandler);
app.get('/api/v1/admin/intel-bundle/:source/:ref', intelBundleAdminHandler);
app.get('/api/v1/google-dorks', validate('query', googleDorksSchema), googleDorksHandler);
app.post('/api/v1/misp', validate('json', mispProxySchema), mispProxyHandler);
app.get('/api/v1/email-rep', emailRepHandler);
app.get('/api/v1/cyber-crime', cybercrimeHandler);
app.get('/api/v1/snapshot', snapshotHandler);
app.get('/api/v1/ioc-snapshot', iocSnapshotHandler);
app.get('/api/v1/intel-dashboard', intelDashboardHandler);
app.get('/api/v1/threat-hunt', validate('query', searchSchema), threatHuntHandler);
app.get('/api/v1/hunt/v2', huntV2Handler);
app.get('/api/v1/pageviews', pageViewsHandler);
app.get('/api/v1/briefings/list', listBriefingsHandler);
app.get('/api/v1/briefings/related', briefingsRelatedHandler);
app.get('/api/v1/briefings/rss', briefingsRssHandler);
app.get('/api/v1/briefings/today', todayBriefingHandler);
app.post('/api/v1/briefings/build', validate('query', briefingBuildSchema), buildBriefingHandler);
app.post('/api/v1/briefings/backfill', validate('query', briefingBackfillSchema), backfillBriefingsHandler);
app.post('/api/v1/briefings/sweep', sweepBriefingsHandler);
app.post('/api/v1/briefings/prune-empty', pruneEmptyBriefingsHandler);
app.post('/api/v1/briefings/delete', validate('query', briefingDeleteSchema), deleteBriefingHandler);
app.get('/api/v1/briefings/for-actor/:slug', briefingsForActorHandler);
app.get('/api/v1/briefings/:slug/render', briefingRenderHandler);
app.get('/api/v1/briefings/:slug/print', briefingPrintHandler);
app.get('/api/v1/briefings/:slug/iocs.txt', briefingIocsTxtHandler);
app.get('/api/v1/briefings/:slug', getBriefingHandler);

// ── Briefing Feedback & Annotations ─────────────────────────────
app.get('/api/v1/briefings/feedback/summary', feedbackSummaryHandler);
app.post('/api/v1/briefings/:slug/feedback', submitFeedbackHandler);
app.get('/api/v1/briefings/:slug/feedback', getFeedbackHandler);
app.post('/api/v1/briefings/:slug/annotations', submitAnnotationHandler);
app.get('/api/v1/briefings/:slug/annotations', getAnnotationsHandler);

app.get('/api/v1/external-resources', listExternalResourcesHandler);
app.post('/api/v1/external-resources', validate('json', createExternalResourceSchema), createExternalResourceHandler);
app.delete('/api/v1/external-resources/:id', deleteExternalResourceHandler);
registerBlogRoutes(app);
// Admin routes MUST be registered BEFORE registerAdminRoutes(app) — the
// case-study admin sub-app at /api/v1/admin has admin.use('*',
// requireAdminMiddleware) which intercepts ALL requests under /api/v1/admin/.
// If these come after, Hono's router matches the sub-app prefix first and
// the auth gate fires before the handler ever runs, rejecting even the
// session-create endpoint that intentionally accepts the token in the body.
app.post('/api/v1/admin/keys', validate('json', adminApiKeyCreateSchema), createApiKeyHandler);
app.get('/api/v1/admin/keys', listApiKeysHandler);
app.delete('/api/v1/admin/keys/:id', revokeApiKeyHandler);
app.post('/api/v1/admin/session', createSessionHandler);
app.delete('/api/v1/admin/session', deleteSessionHandler);
app.post('/api/v1/admin/purge', validate('json', adminPurgeSchema), purgeCacheHandler);
app.post('/api/v1/admin/retention/run', validate('json', adminRetentionSchema), runRetentionHandler);
app.post('/api/v1/admin/retention/telegram-cleanup', telegramCleanupHandler);
app.get('/api/v1/admin/x-cookies', getXCookiesHandler);
app.post('/api/v1/admin/x-cookies', setXCookiesHandler);
app.delete('/api/v1/admin/x-cookies', clearXCookiesHandler);
app.get('/api/v1/admin/x-qids', getXQidsHandler);
app.post('/api/v1/admin/x-qids', setXQidsHandler);
app.delete('/api/v1/admin/x-qids', clearXQidsHandler);
registerAdminRoutes(app);
app.get('/api/v1/malpedia/actor', malpediaActorHandler);
app.get('/api/v1/malpedia/family', malpediaFamilyHandler);
app.get('/api/v1/malpedia/search', malpediaSearchHandler);
app.get('/api/v1/maltrail/list', maltrailListHandler);
app.get('/api/v1/maltrail/fetch', maltrailFetchHandler);
app.get('/api/v1/actor-enrich', actorEnrichHandler);
// Per-route Cache-API burst limiter: actor-profile fans out to 7+ upstream
// calls, so cap it at 10/min/IP. The global rateLimit middleware on
// /api/v1/* still applies on top of this.
app.use('/api/v1/actor-profile', burstLimitActorProfile);
app.get('/api/v1/actor-profile', actorProfileHandler);
app.post('/api/v1/actor-enrich/otx-stream', validate('json', actorEnrichStreamSchema), actorEnrichOtxStreamHandler);
app.get('/api/v1/certstream', certStreamHandler);
app.post('/api/v1/campaign-generator', validate('json', campaignGeneratorSchema), campaignGeneratorHandler);
app.get('/api/v1/actor-cves', actorCvesHandler);
app.get('/api/v1/campaigns', listCampaignsHandler);
app.post('/api/v1/campaigns', validate('json', campaignCreateSchema), saveCampaignHandler);
app.get('/api/v1/campaigns/:id', getCampaignHandler);
app.delete('/api/v1/campaigns/:id', deleteCampaignHandler);
app.post('/api/v1/maltrail-sync', maltrailSyncHandler);
app.get('/api/v1/skeleton-actors', listSkeletonActorsHandler);
app.get('/api/v1/skeleton-actors/:slug', getSkeletonActorHandler);
app.get('/api/v1/malicious-packages', maliciousPackagesHandler);
app.get('/api/v1/package-verdict', packageVerdictHandler);
// depx — supply-chain intelligence feed (OpenSSF malicious packages)
app.get('/api/v1/depx/feed', depxFeedHandler);
app.get('/api/v1/depx/feed/stats', depxFeedStatsHandler);
app.get('/api/v1/depx/feed/check', depxCheckHandler);
app.get('/api/v1/x-tweets', xTweetsHandler);
app.get('/api/v1/x-live', xLiveHandler);
app.get('/api/v1/x-firehose', xFirehoseHandler);
app.post('/api/v1/x-firehose/probe-batch', xFirehoseProbeBatchHandler);
app.get('/api/v1/x-claims', xClaimsHandler);
app.get('/api/v1/x-search', xSearchHandler);
app.get('/api/v1/blocklists/pfsense', blocklistPfSenseHandler);
app.get('/api/v1/blocklists/iptables', blocklistIptablesHandler);
app.get('/api/v1/blocklists/suricata', blocklistSuricataHandler);
app.get('/api/v1/blocklists/meta', blocklistMetaHandler);
app.post('/api/v1/phishing/fetch-page', fetchPageHandler);
app.get('/api/v1/phishing/auto-analyze', phishingAnalyzeAutoHandler);
app.post('/api/v1/phishing/fingerprint', fingerprintHandler);
app.get('/api/v1/unified-search', validate('query', unifiedSearchSchema), unifiedSearchHandler);
// Opt-in AI summary for the omnibox — PUBLIC same-origin (NOT admin-gated, unlike
// /api/v1/ai-summary); query-keyed 1h cache + the global apiKeyRateLimit bound cost.
app.post('/api/v1/unified-search/summarize', unifiedSearchSummarizeHandler);
app.get('/api/v1/relationship-graph', validate('query', relationshipGraphSchema), relationshipGraphHandler);
app.post('/api/v1/rag/index', validate('json', ragIndexSchema), ragIndexHandler);
app.get('/api/v1/rag/query', validate('query', ragQuerySchema), ragQueryHandler);
app.post('/api/v1/rag/index-all', async (c) => {
  const result = await indexAllCorpora(c.env);
  return c.json({ ok: true, ...result });
});
app.post('/api/v1/ai-summary', validate('json', aiSummarySchema), aiSummaryHandler);
app.post('/api/v1/ai-item-summary', validate('json', aiItemSummarySchema), aiItemSummaryHandler);
// SSVC-V triage — decision-model-as-a-service. CVE → Act/Prioritise/Track/Watch
app.post('/api/v1/ssvc/triage', ssvcTriageHandler);
app.get('/api/v1/ssvc/triage/:id', ssvcGetHandler);
app.get('/api/v1/ssvc/stats', ssvcStatsHandler);

// Threat Dossier — 5W+H + Diamond Model per entity
app.post('/api/v1/dossier', dossierHandler);
app.get('/api/v1/dossier/:type/:value', dossierGetHandler);

// Phase 2: per-report AI primitives. Backs the /threatintel/report-analyzer
// page and is also useful as standalone tools (TTP map, 5W grid, image-OCR).
app.post('/api/v1/ttp-extract', ttpExtractHandler);
app.post('/api/v1/fivew', fivewHandler);
app.post('/api/v1/image-ioc', imageIocHandler);
// Phase 3: unified per-report analyzer (summary + IOCs + TTPs + 5W +
// image-IOCs + STIX bundle, all in one round-trip).
app.post('/api/v1/report-analyzer', reportAnalyzerHandler);
app.post('/api/v1/report-analyzer/render', reportAnalyzerRenderHandler);
app.get('/api/v1/saved-reports', listSavedReports);
app.get('/api/v1/saved-reports/timeline', getTimeline);
app.get('/api/v1/saved-reports/:id', getSavedReport);
app.post('/api/v1/saved-reports', saveReport);
app.delete('/api/v1/saved-reports/:id', deleteSavedReport);
app.post('/api/v1/saved-reports/:id/branding', setBranding);
app.post('/api/v1/saved-reports/:id/share', shareSavedReport);
app.delete('/api/v1/saved-reports/:id/share', unshareSavedReport);
// Public share DATA endpoint — capability-token routes are exempt from the
// API-key gate (see auth.ts); the SPA page /share/report/:token fetches this.
app.get('/api/v1/public/report/:token', getSharedReport);
app.post('/api/v1/saved-reports/correlate', correlateIocs);
app.post('/api/v1/copilot/investigate', validate('json', copilotInvestigateSchema), copilotInvestigateHandler);
app.get('/api/v1/copilot/investigate', copilotInvestigateHandler);
app.post('/api/v1/copilot/chat', copilotChatHandler);
app.get('/api/v1/copilot/chat/sessions', copilotChatListHandler);
app.get('/api/v1/copilot/chat/:sessionId/stream', copilotChatStreamHandler);
app.get('/api/v1/copilot/chat/:sessionId', copilotChatHistoryHandler);
app.delete('/api/v1/copilot/chat/:sessionId', copilotChatDeleteHandler);
app.post('/api/v1/copilot/chat/:sessionId/cancel', copilotChatCancelHandler);
app.post('/api/v1/copilot/pivots', copilotPivotHandler);
app.post('/api/v1/copilot/follow-ups', copilotFollowUpsHandler);
app.post('/api/v1/copilot/bulk-ioc', copilotBulkIocHandler);
app.post('/api/v1/copilot/rules', copilotRulesSaveHandler);
app.get('/api/v1/copilot/rules', copilotRulesListHandler);
app.delete('/api/v1/copilot/rules/:id', copilotRulesDeleteHandler);
// Vera — multi-mode conversational CTI (4 chat modes: Ask, Investigate, Draft, Challenge)
app.post('/api/v1/agents/chat', veraChatHandler);
app.get('/api/v1/agents/chat/modes', veraChatModesHandler);
app.get('/api/v1/agents/chat/roles', veraChatRolesHandler);
app.get('/api/v1/agents/chat/sessions', veraSessionsListHandler);
app.get('/api/v1/agents/chat/:sessionId/stream', veraChatStreamHandler);
app.get('/api/v1/agents/chat/:sessionId', veraChatHistoryHandler);
app.delete('/api/v1/agents/chat/:sessionId', veraChatDeleteHandler);
app.post('/api/v1/agents/chat/:sessionId/cancel', veraChatCancelHandler);

// ── Threat Landscape-style APIs ─────────────────────────────────
// STIX Bundles (PostgREST-style): /api/v1/stix_bundles
app.get('/api/v1/stix_bundles', stixBundlesHandler);

// Actionable IOCs (PostgREST-style): /api/v1/actionable_iocs
app.get('/api/v1/actionable_iocs', actionableIocsHandler);

// Per-type active IOC endpoints
const IOC_TYPES = ['ipv4', 'ipv6', 'domain', 'url', 'md5', 'sha1', 'sha256'];
for (const t of IOC_TYPES) {
  app.get(`/api/v1/iocs_${t}`, createIocTypeHandler(t));
}
app.post('/api/v1/report/build', validate('json', reportBuildSchema), buildReportHandler);
app.get('/api/v1/report/:id', getReportHandler);
app.get('/api/v1/report/:id/stream', streamReportHandler);
// File ingestion (SP2): upload PDF/DOCX/image/HTML/text → STIX bundle. Admin-gated
// via the /api/v1/report ADMIN_GATED_PREFIXES entry (untrusted uploads trigger
// Workers AI vision OCR + a provider fan-out, so it must not be anonymous).
app.post('/api/v1/report/ingest', reportIngestHandler);
app.post('/api/v1/automation/run', validate('json', automationRunSchema), automationRunHandler);
app.get('/api/v1/maltiverse/search', maltiverseSearchHandler);
app.get('/api/v1/inquest/search', inquestSearchHandler);
app.get('/api/v1/hackertarget/dns', hackertargetDnsHandler);
app.get('/api/v1/hackertarget/reverse-ip', hackertargetReverseIpHandler);
app.get('/api/v1/radar/domain', radarDomainHandler);
app.get('/api/v1/certspotter/search', certspotterSearchHandler);
app.get('/api/v1/triage/search', triageSearchHandler);

// ── Report Parser ─────────────────────────────────────────────────
app.post('/api/v1/report/parse', reportParserHandler);

// ── IOC Lifecycle ─────────────────────────────────────────────────
app.get('/api/v1/ioc-lifecycle', validate('query', iocLifecycleSchema), iocLifecycleHandler);
app.get('/api/v1/ioc-lifecycle/trending', validate('query', iocTrendingSchema), iocLifecycleTrendingHandler);
app.get('/api/v1/ioc-lifecycle/stats', iocLifecycleStatsHandler);

// ── AI Rule Generator ────────────────────────────────────────────
app.post('/api/v1/rules/generate', validate('json', ruleGenerateSchema), ruleGeneratorHandler);
app.post('/api/v1/rules/validate', validate('json', ruleValidateSchema), ruleValidateHandler);

// ── FPLENS — False Positive Likelihood Analyzer ─────────────────
// Open to all callers (not admin-gated). The endpoint reads detection
// rules + sample hits / env context and returns a structured verdict
// on FP risk + tuning guidance. Workers AI with Groq fallback.
app.post('/api/v1/fplens/analyze', validate('json', fplensAnalyzeSchema), fplensAnalyzeHandler);
// Legacy routes for backward compatibility
app.post('/api/v1/yara/generate', validate('json', ruleGenerateSchema), ruleGeneratorHandler);
app.post('/api/v1/yara/validate', validate('json', ruleValidateSchema), ruleValidateHandler);

// ── CT Domain Monitor ────────────────────────────────────────────
app.get('/api/v1/ct-monitor/watched', ctWatchedListHandler);
app.post('/api/v1/ct-monitor/watch', ctWatchAddHandler);
app.delete('/api/v1/ct-monitor/watch/:domain', ctWatchRemoveHandler);
app.get('/api/v1/ct-monitor/certs', validate('query', ctCertsSchema), ctCertsHandler);

// ── TAXII 2.1 Server ────────────────────────────────────────────
app.get('/api/taxii2/', taxiiDiscoveryHandler);
app.get('/api/taxii2/collections/', taxiiCollectionsHandler);
app.get('/api/taxii2/collections/:id/', taxiiCollectionHandler);
app.get('/api/taxii2/collections/:id/objects/', taxiiObjectsHandler);
app.post('/api/taxii2/collections/:id/objects/', taxiiAddObjectsHandler);

// ── Stealer Log Parser ──────────────────────────────────────────
app.post('/api/v1/stealer/parse', stealerParserHandler);

// ── Bloom Filter ─────────────────────────────────────────────────
app.get('/api/v1/bloom/stats', bloomStatsHandler);
app.get('/api/v1/bloom/:type', bloomFilterHandler);
app.post('/api/v1/bloom/check', validate('json', bloomCheckSchema), bloomCheckHandler);

// ── Threat Graph ─────────────────────────────────────────────────
app.get('/api/v1/graph/node/:type/:value', graphNodeHandler);
app.get('/api/v1/graph/path', graphPathHandler);
app.get('/api/v1/graph/communities', graphCommunitiesHandler);
app.get('/api/v1/graph/stats', graphStatsHandler);
// Cross-report knowledge graph snapshot. Backs the explorer page.
app.get('/api/v1/graph/cross-report', graphCrossReportHandler);
app.post('/api/v1/graph/ingest', validate('query', graphIngestSchema), graphIngestManualHandler);

// ── Hunting & IR Tools ─────────────────────────────────────────────
app.post('/api/v1/hunting-queries/generate', validate('json', huntingQuerySchema), huntingQueryHandler);
app.get('/api/v1/sandbox/lookup', sandboxLookupHandler);
// Free "lite 0x12" — multi-provider hash fan-out + public-sandbox deep links.
// Always on; no bridge secret required. See docs/free/sample-scan.md.
app.post('/api/v1/sample/scan', sampleScanHandler);
app.get('/api/v1/sample/scan', sampleScanHandler);
app.post('/api/v1/ir-playbooks/generate', validate('json', irPlaybookSchema), irPlaybookHandler);

// ── Temporal Analysis ────────────────────────────────────────────
app.get('/api/v1/temporal/timeline', temporalTimelineHandler);
app.get('/api/v1/temporal/campaigns', temporalCampaignsHandler);
app.get('/api/v1/temporal/velocity', temporalVelocityHandler);
app.get('/api/v1/temporal/predict', temporalPredictHandler);

// ── Attack Chain ─────────────────────────────────────────────────
app.post('/api/v1/attack-chain/reconstruct', validate('json', attackChainReconstructSchema), attackChainHandler);
app.get('/api/v1/attack-chain/techniques', attackChainTechniquesHandler);

// ── Actor DNA ───────────────────────────────────────────────────
app.post('/api/v1/threat-intel/actor-dna/match', validate('json', actorDnaMatchSchema), actorDnaMatchHandler);
app.get('/api/v1/threat-intel/actor-dna', actorDnaListHandler);
app.get('/api/v1/threat-intel/actor-dna/:actorId', actorDnaGetHandler);
app.get('/api/v1/threat-intel/actor-dna/compare/:actor1/:actor2', actorDnaCompareHandler);

// ── Entity Resolution ──────────────────────────────────────────────
app.get('/api/v1/threat-intel/entities/resolve', entityResolveHandler);
app.post(
  '/api/v1/threat-intel/entities/extract',
  validate('json', threatIntelEntityExtractSchema),
  entityExtractHandler
);
app.post(
  '/api/v1/threat-intel/entities/profile',
  validate('json', threatIntelEntityProfileSchema),
  entityProfileHandler
);

// ── Observe 360 ──────────────────────────────────────────────────
app.get('/api/v1/threat-intel/observe', observeHandler);

// ── Campaign Lifecycle ──────────────────────────────────────────
app.post('/api/v1/threat-intel/campaign/analyze', validate('json', campaignAnalyzeSchema), campaignAnalyzeHandler);
app.get('/api/v1/threat-intel/campaign/techniques', campaignTechniquesHandler);

// ── Predictive Intelligence ─────────────────────────────────────
app.get('/api/v1/threat-intel/predictive/forecasts', predictiveForecastsHandler);
app.get('/api/v1/threat-intel/predictive/sector-risks', predictiveSectorRisksHandler);
app.post(
  '/api/v1/threat-intel/predictive/attribution',
  validate('json', predictiveAttributionSchema),
  predictiveAttributionHandler
);
app.get('/api/v1/threat-intel/predictive/gaps', predictiveGapsHandler);
app.get('/api/v1/threat-intel/predictive/report', predictiveReportHandler);
app.get('/api/v1/threat-intel/collection-slo', feedStatusHandler);
app.get('/api/v1/threat-intel/pirs', pirListHandler);
app.get('/api/v1/threat-intel/pirs/relevant', pirRelevantHandler);
app.get('/api/v1/threat-intel/pirs/alert', pirAlertHandler);
app.get('/api/v1/threat-intel/pirs/alerts', pirAlertListHandler);
app.get('/api/v1/threat-intel/pirs/routing', pirRoutingHandler);
app.patch('/api/v1/threat-intel/pirs/alerts/:id/acknowledge', validate('json', pirAlertAckSchema), pirAlertAckHandler);
app.post('/api/v1/threat-intel/pirs/alerts/acknowledge-all', pirAlertAckAllHandler);
app.post('/api/v1/threat-intel/pirs', validate('json', pirCreateSchema), pirCreateHandler);
// NOTE: the static `/pirs/*` routes above MUST stay before these `:id` routes —
// Hono matches in registration order, so `/pirs/routing` would otherwise be
// captured by `/pirs/:id` (id="routing") and 404 as "PIR not found".
app.get('/api/v1/threat-intel/pirs/:id', pirDetailHandler);
app.put('/api/v1/threat-intel/pirs/:id', validate('json', pirUpdateSchema), pirUpdateHandler);
app.delete('/api/v1/threat-intel/pirs/:id', pirDeleteHandler);
app.post('/api/v1/threat-intel/feedback', validate('json', threatIntelFeedbackSchema), feedbackCreateHandler);
app.get('/api/v1/threat-intel/feedback', feedbackListHandler);
app.get('/api/v1/threat-intel/feedback/aggregate', feedbackAggregateHandler);
app.delete('/api/v1/threat-intel/feedback/:id', feedbackDeleteHandler);
app.get('/api/v1/source-reliability', sourceReliabilityHandler);
app.get('/api/v1/maturity', maturityHandler);

// ── ACH Generator ───────────────────────────────────────────────
app.post('/api/v1/threat-intel/ach', validate('json', achGenerateSchema), achHandler);

// ── Novelty Detection ──────────────────────────────────────────
app.get('/api/v1/threat-intel/novelty', noveltyHandler);
app.post('/api/v1/threat-intel/novelty/batch', validate('json', noveltyBatchSchema), noveltyBatchHandler);

// ── Intelligence Assessments ────────────────────────────────────
app.get('/api/v1/threat-intel/assessments', assessmentListHandler);
app.post('/api/v1/threat-intel/assessments', validate('json', assessmentSchema), assessmentCreateHandler);
app.get('/api/v1/threat-intel/assessments/:id', assessmentDetailHandler);
app.put('/api/v1/threat-intel/assessments/:id', validate('json', assessmentUpdateSchema), assessmentUpdateHandler);
app.delete('/api/v1/threat-intel/assessments/:id', assessmentDeleteHandler);

// ── Cross-Correlation Intelligence ──────────────────────────────
app.post('/api/v1/threat-intel/correlate', validate('json', correlationSchema), correlateHandler);

// ── Dark Web Economics ──────────────────────────────────────────

// ── Cross-Campaign Correlation ─────────────────────────────────
app.get('/api/v1/threat-intel/cross-campaign/correlations', crossCampaignCorrelationHandler);

// ── Domain Intelligence ──────────────────────────────────────────
app.get('/api/v1/domain-rep', domainRepHandler);
app.get('/api/v1/domain-monitor', domainMonitorHandler);
app.get('/api/v1/domain/webcheck', domainWebcheckHandler);

// ── Domain WHOIS History & Pivot ──────────────────────────────────
app.get('/api/v1/domain/history', domainHistoryHandler);
app.get('/api/v1/domain/history/changes', domainChangesHandler);
app.get('/api/v1/domain/history/pivot', domainPivotHandler);
app.get('/api/v1/domain/history/stats', domainHistoryStatsHandler);
app.get('/api/v1/domain/history/search', domainRegistrantSearchHandler);
app.post('/api/v1/domain/history/snapshot', validate('json', domainSnapshotSchema), domainSnapshotHandler);

// ── Open Directory Scanner ───────────────────────────────────────
app.post('/api/v1/open-dir/scan', validate('json', openDirScanSchema), openDirectoryScanHandler);

// ── Exposed Host Intelligence ────────────────────────────────────
app.get('/api/v1/exposed-host', exposedHostHandler);
app.get('/api/v1/exploit-db', validate('query', exploitDbSchema), exploitDbHandler);
app.get('/api/v1/fusion-exposure', fusionExposureHandler);

// ── Risk Register ───────────────────────────────────────────────────
app.get('/api/v1/risk-register', riskRegisterListHandler);
app.get('/api/v1/risk-register/stats', riskRegisterStatsHandler);
app.get('/api/v1/risk-register/:id', riskRegisterGetHandler);
app.post('/api/v1/risk-register', riskRegisterCreateHandler);
app.put('/api/v1/risk-register/:id', riskRegisterUpdateHandler);
app.delete('/api/v1/risk-register/:id', riskRegisterDeleteHandler);

// ── Attack Path Graph ────────────────────────────────────────────────
app.get('/api/v1/attack-path-graph', attackPathGraphHandler);

// ── GRC Compliance Evidence ──────────────────────────────────────────
app.get('/api/v1/grc/frameworks', grcListFrameworks);
app.get('/api/v1/grc/frameworks/:id', grcGetFramework);
app.put('/api/v1/grc/frameworks/:id', grcUpdateFramework);
app.get('/api/v1/grc/controls', grcListControls);
app.get('/api/v1/grc/controls/:id', grcGetControl);
app.post('/api/v1/grc/controls', grcCreateControl);
app.put('/api/v1/grc/controls/:id', grcUpdateControl);
app.delete('/api/v1/grc/controls/:id', grcDeleteControl);
app.get('/api/v1/grc/evidence', grcListEvidence);
app.get('/api/v1/grc/evidence/:id', grcGetEvidence);
app.post('/api/v1/grc/evidence', grcCreateEvidence);
app.put('/api/v1/grc/evidence/:id', grcUpdateEvidence);
app.delete('/api/v1/grc/evidence/:id', grcDeleteEvidence);
app.get('/api/v1/grc/stats', grcStats);

// ── Vulnerability Ops (VOC) ─────────────────────────────────────────
app.get('/api/v1/voc', vocList);
app.get('/api/v1/voc/stats', vocStats);
app.get('/api/v1/voc/:id', vocGet);
app.post('/api/v1/voc', vocCreate);
app.put('/api/v1/voc/:id', vocUpdate);
app.delete('/api/v1/voc/:id', vocDelete);

// ── Ransomware Quantification ───────────────────────────────────────
app.get('/api/v1/ransomware', ransomList);
app.get('/api/v1/ransomware/stats', ransomStats);
app.get('/api/v1/ransomware/:id', ransomGet);
app.post('/api/v1/ransomware', ransomCreate);
app.put('/api/v1/ransomware/:id', ransomUpdate);
app.delete('/api/v1/ransomware/:id', ransomDelete);

// ── Patch & Task Manager (PTM) ──────────────────────────────────────
app.get('/api/v1/ptm/patches', ptmListPatches);
app.get('/api/v1/ptm/patches/:id', ptmGetPatch);
app.post('/api/v1/ptm/patches', ptmCreatePatch);
app.put('/api/v1/ptm/patches/:id', ptmUpdatePatch);
app.delete('/api/v1/ptm/patches/:id', ptmDeletePatch);
app.get('/api/v1/ptm/windows', ptmListWindows);
app.get('/api/v1/ptm/windows/:id', ptmGetWindow);
app.post('/api/v1/ptm/windows', ptmCreateWindow);
app.put('/api/v1/ptm/windows/:id', ptmUpdateWindow);
app.delete('/api/v1/ptm/windows/:id', ptmDeleteWindow);
app.get('/api/v1/ptm/stats', ptmStats);

// ── SOC Automation ──────────────────────────────────────────────────
app.get('/api/v1/soc/playbooks', socListPlaybooks);
app.get('/api/v1/soc/playbooks/:id', socGetPlaybook);
app.post('/api/v1/soc/playbooks', socCreatePlaybook);
app.put('/api/v1/soc/playbooks/:id', socUpdatePlaybook);
app.delete('/api/v1/soc/playbooks/:id', socDeletePlaybook);
app.post('/api/v1/soc/playbooks/:id/execute', socExecutePlaybook);
app.get('/api/v1/soc/runs', socListRuns);
app.get('/api/v1/soc/runs/:id', socGetRun);
app.get('/api/v1/soc/stats', socStats);

app.get('/api/v1/security-updates', validate('query', securityUpdatesSchema), securityUpdatesHandler);
app.get('/api/v1/cisa-kev', validate('query', cisaKevSchema), cisaKevHandler);
import { stixIpEnrichHandler, stixIpEnrichBatchHandler } from './routes/stix-ip-enrich';
app.get('/api/v1/si/enrich-ip-stix', stixIpEnrichHandler);
app.post('/api/v1/si/enrich-ip-stix-batch', stixIpEnrichBatchHandler);
app.get('/api/v1/cert-in', validate('query', certInSchema), certInHandler);
app.get('/api/v1/supply-chain-attacks', validate('query', supplyChainAttacksSchema), supplyChainAttacksHandler);
app.get('/api/v1/k8s-cve', validate('query', k8sCveSchema), k8sCveHandler);
app.get('/api/v1/misp-galaxy-actors', validate('query', mispGalaxyActorsSchema), mispGalaxyActorsHandler);
app.get('/api/v1/cloud-threat-landscape', validate('query', cloudThreatLandscapeSchema), cloudThreatLandscapeHandler);
app.get('/api/v1/ransomwhere', validate('query', ransomwhereSchema), ransomwhereHandler);
app.get('/api/v1/disarm-framework', validate('query', disarmFrameworkSchema), disarmFrameworkHandler);
app.get('/api/v1/attack-flow-library', validate('query', attackFlowLibrarySchema), attackFlowLibraryHandler);
app.get('/api/v1/volexity-threat-intel', validate('query', volexityThreatIntelSchema), volexityThreatIntelHandler);
app.get('/api/v1/passive-dns', validate('query', passiveDnsSchema), passiveDnsLookupHandler);
app.get('/api/v1/passive-dns/reverse', passiveDnsReverseHandler);
app.get('/api/v1/passive-dns/overlap', passiveDnsOverlapHandler);
app.get('/api/v1/passive-dns/stats', passiveDnsStatsHandler);

// IOC Watchlist — proactive alerting on any indicator type
app.post('/api/v1/ioc-watchlist', iocWatchlistCreateHandler);
app.get('/api/v1/ioc-watchlist', iocWatchlistListHandler);
app.get('/api/v1/ioc-watchlist/stats', iocWatchlistStatsHandler);
app.get('/api/v1/ioc-watchlist/alerts', iocWatchlistAlertsHandler);
app.get('/api/v1/ioc-watchlist/:id', iocWatchlistGetHandler);
app.delete('/api/v1/ioc-watchlist/:id', iocWatchlistDeleteHandler);

// ── Actor Watchlist & Weekly Digest ────────────────────────────────
app.get('/api/v1/watchlist/actors', watchlistActorsListHandler);
app.post('/api/v1/watchlist/actors', watchlistActorsAddHandler);
app.delete('/api/v1/watchlist/actors/:id', watchlistActorsDeleteHandler);
app.get('/api/v1/watchlist/actors/:actor/activity', watchlistActorActivityHandler);
app.post('/api/v1/watchlist/digest', watchlistDigestGenerateHandler);
app.get('/api/v1/watchlist/digests', watchlistDigestsListHandler);
app.get('/api/v1/watchlist/digest/:id', watchlistDigestGetHandler);

app.get('/api/v1/github-security', validate('query', githubSecuritySchema), gitHubSecurityHandler);
app.get('/api/v1/github-security/recent/meta', gitHubSecurityRecentMetaHandler);

// ── Curated landscapes (OWASP AI + start.me mirror) ────────────────
// Public reads; both payloads are tiny JSON trees cached in KV by a
// daily cron (see worker/scheduled.ts). The `*meta` endpoints power
// the "synced 3h ago" badge in the UI.
app.get('/api/v1/owasp-ai-landscape', getOwaspAiLandscapeHandler);
app.get('/api/v1/owasp-ai-landscape/meta', getOwaspAiLandscapeMetaHandler);
app.get('/api/v1/curated-toolbox', getCuratedToolboxHandler);
app.get('/api/v1/curated-toolbox/meta', getCuratedToolboxMetaHandler);
app.get('/api/v1/curated-certs', getCuratedCertsHandler);
app.get('/api/v1/curated-certs/meta', getCuratedCertsMetaHandler);
app.get('/api/v1/redhunt-insights', getRedHuntInsightsHandler);
app.get('/api/v1/predictions', predictionsHandler);

app.get('/api/v1/dashboard', dashboardHandler);
app.get('/api/v1/dashboard/watchlist', getWatchlistHandler);
app.post('/api/v1/dashboard/watchlist', validate('json', watchlistUpdateSchema), updateWatchlistHandler);
app.get('/api/v1/watches', listWatchesHandler);
app.post('/api/v1/watches', validate('json', watchCreateSchema), createWatchHandler);
app.put('/api/v1/watches/:id', validate('json', watchUpdateSchema), updateWatchHandler);
app.delete('/api/v1/watches/:id', deleteWatchHandler);
app.get('/api/v1/watches/log', alertLogHandler);

/* ─── Investigation Notebooks ─────────────────────────────────────── */
app.get('/api/v1/notebooks', listNotebooksHandler);
app.post('/api/v1/notebooks', createNotebookHandler);
app.get('/api/v1/notebooks/stats', notebookStatsHandler);
app.get('/api/v1/notebooks/:id', getNotebookHandler);
app.put('/api/v1/notebooks/:id', updateNotebookHandler);
app.delete('/api/v1/notebooks/:id', deleteNotebookHandler);
app.post('/api/v1/notebooks/:id/entries', addEntryHandler);
app.put('/api/v1/notebooks/:notebookId/entries/:entryId', updateEntryHandler);
app.delete('/api/v1/notebooks/:notebookId/entries/:entryId', deleteEntryHandler);
/* ─── Export Hub ──────────────────────────────────────────────────── */
// Handlers live in routes/export.ts: each parses the body via safeJsonBody
// (400 on malformed input, not a 500), validates the minimal shape it needs,
// and returns a download with the correct Content-Type + Content-Disposition.
app.post('/api/v1/export/stix', exportStixHandler);
app.post('/api/v1/export/misp', exportMispHandler);
app.post('/api/v1/export/sigma', exportSigmaHandler);
app.post('/api/v1/export/yara', exportYaraHandler);
app.post('/api/v1/export/snort', exportSnortHandler);
app.post('/api/v1/export/suricata', exportSuricataHandler);
app.post('/api/v1/export/csv', exportCsvHandler);
app.post('/api/v1/export/pfsense', exportPfSenseHandler);

// SI: server-side SVG rendering. GET with ?slug=<skill> returns image/svg+xml directly;
// POST with JSON/YAML body returns the same SVG wrapped in JSON (with bytes + widgetCount).
// See worker/lib/si-svg-renderer.ts for supported widget types.
app.get('/api/v1/si/render', siRenderHandler);
app.post('/api/v1/si/render', siRenderHandler);

// SI edge tools (H3AD-SEC replicas): PARSE-X, MAILSCOPE, SHIFTLOG, HYPOS, PROMPTVAULT
// Mounted as a sub-router so all routes get the /api/v1/ prefix via the
// parent app. Each tool runs in a few ms on the edge — no external calls
// except HYPOS which uses the ASSETS binding for SI skill matching.
app.route('/api/v1', siEdgeToolsRouter);

// Security Investigator (replicated from SCStelz/security-investigator, MIT).
// Public data lives in dist/data/si/ and is read via env.ASSETS. Cached at the edge.
app.get('/api/v1/si/index', siIndexHandler);
app.get('/api/v1/si/skills', siSkillsHandler);
app.get('/api/v1/si/skills/:slug', siSkillHandler);
app.get('/api/v1/si/queries', siQueriesHandler);
app.get('/api/v1/si/queries/:domain/:file', siQueryHandler);
app.get('/api/v1/si/query', siQueryBySlugHandler);
app.get('/api/v1/si/automations', siAutomationsHandler);
app.get('/api/v1/si/automations/:slug', siAutomationHandler);
app.get('/api/v1/si/docs', siDocsHandler);
app.get('/api/v1/si/docs/:slug', siDocHandler);
app.get('/api/v1/si/ref', siRefListHandler);
app.get('/api/v1/si/ref/:name', siRefHandler);
app.get('/api/v1/si/routing-prompt', siRoutingPromptHandler);
app.get('/api/v1/si/scripts', siScriptsHandler);
app.get('/api/v1/si/scripts/:name', siScriptHandler);

// AI Threat Actors tracker — confirmed real-world threat-actor uses of AI/LLMs.
// Data from github.com/cybershujin/Threat-Actors-use-of-Artifical-Intelligence (MIT).
// Source: https://cybershujin.github.io/Threat-Actors-use-of-Artifical-Intelligence/
app.route('/api/v1', aiThreatsRouter);

// Ransomware Groups directory — Sinon-style leak-site group reference.
// Static manifest in public/data/ransomware-groups/ (Ransomlook + ransomware.live).
app.route('/api/v1', ransomwareGroupsRouter);

// Anarchy — kazamadono.github.io course catalog (1708 courses, daily sync).
// Static manifest in public/data/anarchy/ (replicated with attribution).
app.route('/api/v1', anarchyRouter);

// AI Escape Watch — agent containment-failure registry.
// Static manifest in public/data/ai-escape/ (curatorial seed, reviewed via PR).
app.route('/api/v1', aiEscapeRouter);

// AI Security hub — matrix + incidents + escape parity + vulns + advisories + research.
// Static manifest in public/data/ai-security/ (daily sync, reviewed via PR).
app.route('/api/v1', aiSecurityRouter);

// OSS Feed Registry — curated catalog of 145+ free open-source threat intel feeds.
// Data from github.com/Bert-JanP/Open-Source-Threat-Intel-Feeds (BSD-3-Clause).
app.route('/api/v1', ossFeedsRouter);

// Threat Intel vertical (OpenThreat + cyber_threat_intel + Daily-Hunt references).
// CVE/KEV/IOC/sector briefs served from public/data/threat-intel/ via env.ASSETS.
app.route('/api/v1', threatIntelRouter);

// Daily Briefs — AI-generated intelligence briefs (cyber/deepfake/disaster/maritime).
// Served under the global /api/v1/* 'external-only' auth: same-origin SPA requests
// pass through without a key; external callers need an API key.
app.route('/api/v1', dailyBriefsRouter);

// Webamon Daily Threat Brief — campaign intelligence from webamon-org/Daily-Threat-Brief (Apache-2.0).
app.route('/api/v1', webamonDtbRouter);

// PCMedicalist Intelligence Feed — daily security-intel digest (slim mirror
// in public/data/pcmedicalist/ + live deep-dive day feed proxy). Data from
// github.com/PCMedicalist/pcmedicalist-intellegence-feed (CC BY 4.0).
app.route('/api/v1', pcmedicalistRouter);

// WinReg DFIR vertical — Windows Registry forensic artifact reference.
// Data from github.com/dfir-scripts/dfir-scripts.github.io (MIT).
// Upstream: https://dfir-scripts.github.io/registry/
app.route('/api/v1', winRegRouter);

// Signature-Base — YARA rule set + IOC lists from
// github.com/Neo23x0/signature-base (Detection Rule License 1.1).
app.route('/api/v1', sigBaseRouter);

// Breach Watch — live breach/leak data from 6 free public trackers
// (ransomware.live + ransomlook.io + Darkfield + RecentBreaches.com +
// CTI.FYI + XposedOrNot). Data ships in public/data/breach-watch/.
app.route('/api/v1', breachWatchRouter);

// OSINT Portal Directory — curated list of 40 free/paid OSINT portals.
// Data ships in public/data/osint/ built by scripts/build-osint-manifest.mjs.
app.route('/api/v1', osintRouter);

// CTI Bookmarks — 387 curated CTI links (Operational/Tactical/Strategic/Tools)
// from Chick3nHawk01/Open_Source-CTI-Tooling, each tagged live/reference/missing.
// Data ships in public/data/cti-bookmarks/ built by scripts/build-cti-bookmarks.mjs.
app.route('/api/v1', ctiBookmarksRouter);

// LOTS Project — 175 trusted sites abusable for phishing/C2/exfiltration.
// Data ships in public/data/lots/ built by scripts/build-lots-manifest.mjs.
app.route('/api/v1', lotsRouter);

// MalAPI.io — 370 Windows APIs abused by attackers, by category + library.
// Data ships in public/data/malapi/ built by scripts/build-malapi-manifest.mjs.
app.route('/api/v1', malapiRouter);

// MITRE CAR — 102 cyber analytics with ATT&CK coverage + D3FEND mappings.
// Data ships in public/data/car/ built by scripts/build-car-manifest.mjs.
app.route('/api/v1', carRouter);

// MITRE CAPEC — 559 attack patterns with CWE/ATT&CK cross-references.
// Data ships in public/data/capec/ built by scripts/build-capec-manifest.mjs.
app.route('/api/v1', capecRouter);

// HijackLibs — 608 DLL hijacking candidates with vulnerable executables.
// Data ships in public/data/hijacklibs/ built by scripts/build-hijacklibs-manifest.mjs.
app.route('/api/v1', hijacklibsRouter);

// VERIS Framework — 68 incident-taxonomy fields (Actor/Action/Asset/Attribute).
// Data ships in public/data/veris/ built by scripts/build-veris-manifest.mjs.
app.route('/api/v1', verisRouter);

// MITRE Engage — 53 adversary-engagement approaches across 9 goals.
// Data ships in public/data/engage/ built by scripts/build-engage-manifest.mjs.
app.route('/api/v1', engageRouter);

// CAIRN — Cisco Talos Cognitive Artifact Intelligence Research Network (MIT):
// 26 tiered YARA rules (T1/T2/T3) over VT-metadata scan text, 27 acquisition
// filters, A0–A11 archetypes, 10 family reports. Pure local scan engine.
// Data ships in public/data/cairn/ built by scripts/build-cairn-manifest.mjs.
app.route('/api/v1', cairnRouter);

// NOVA — prompt pattern matching (nova-framework engine + nova-rules, MIT):
// 69 .nov rules (keywords/semantics/llm/condition). Edge evaluates keywords
// only; semantics/llm are fail-closed gates. Data ships in public/data/nova/
// built by scripts/build-nova-manifest.mjs.
app.route('/api/v1', novaRouter);

// Denali — evidence-led AI security reference (transilienceai/denali,
// Apache-2.0): 9 deterministic rules, domain taxonomy, 38 ADR/guide docs,
// plus stateless sliding-window checks. Data ships in public/data/denali/
// built by scripts/build-denali-manifest.mjs.
app.route('/api/v1', denaliRouter);
app.route('/api/v1', aiPlaybookRouter);

// Reports & Reading Library — curated list of 28 security reports,
// frameworks, standards, and learning resources. Data ships in
// public/data/reports/ built by scripts/build-reports-manifest.mjs.
app.route('/api/v1', reportsRouter);

// Active Campaigns Tracker — curated list of currently active threat
// campaigns with writeup links, TTPs, and actor attribution.
// Data ships in public/data/campaigns/ built by scripts/build-campaigns-manifest.mjs.
app.route('/api/v1', campaignsRouter);

// APT Actors vertical — ETDA Threat Group Cards (504 actors) + APTmap graph.
// Data ships in public/data/apt-actors/ built by scripts/build-etda-actors.mjs.
// License: CC BY-NC-SA 4.0 (ETDA), MIT (APTmap design reference).
app.route('/api/v1', etdaActorsRouter);

// Traceix — SHA-256 hash antivirus/reputation lookup via PCEF traceix.com API.
// Endpoint: GET /api/v1/traceix/lookup?hash=<sha256>
// Requires TRACEIX_API_KEY Worker secret.
app.route('/api/v1', traceixRouter);

// Profile GitHub stat cards — self-hosted SVG replacements for the flaky
// github-readme-stats / streak-stats services used on the profile README.
// Endpoint: GET /api/v1/profile/gh-stats?type=overview|langs|streak&theme=dark|light
// Public (no key) so GitHub's image proxy can render the badges.
app.route('/api/v1', profileStatsRouter);

// NHI Scanner — non-human & agent identity risk scanner (port of
// github.com/rpmsft9/nhi-scan, MIT). Deterministic tiering vs. OWASP NHI
// Top 10; pure local computation, no secrets required.
// Endpoints: POST /api/v1/nhi/scan   — scan an inventory (list or {identities})
//            GET  /api/v1/nhi/catalog — OWASP catalog + tiering rules
app.route('/api/v1', nhiScanRouter);

// Whoxy — reverse WHOIS lookup by email/name/company/keyword.
// Requires WHOXY_API_KEY Worker secret.
// Endpoint: GET /api/v1/whoxy/reverse?q=<term>&type=email|name|company|keyword
app.route('/api/v1', whoxyRouter);

// Validity Heatwave — cold-email sending-domain blocklist (keyless scrape proxy).
// Endpoint: GET /api/v1/heatwave/lookup?domain=<sending-domain>
app.get('/api/v1/heatwave/lookup', heatwaveLookupHandler);

// Global Threat Actor Monitor — RSS proxy for client-side APT detection.
// Endpoints: /api/v1/threat-monitor/*
app.route('/api/v1', threatMonitorRouter);

// Truecaller — reverse phone lookup (caller name, carrier, spam score).
// Requires TRUECALLER_API_KEY Worker secret.
// Endpoint: GET /api/v1/truecaller/lookup?phone=<number>
app.route('/api/v1', truecallerRouter);

// FullHunt — attack surface discovery.
// Requires FULLHUNT_API_KEY Worker secret (free at fullhunt.io).
// Endpoints: GET /api/v1/fullhunt/domain?domain=
//            GET /api/v1/fullhunt/host?host=
//            GET /api/v1/fullhunt/subdomains?domain=
app.route('/api/v1', fullhuntRouter);

// OpenSanctions — sanctions, PEP, and crime entity search.
// No API key required (rate-limited public API).
// Endpoints: GET /api/v1/opensanctions/search?q=&limit=
//            GET /api/v1/opensanctions/entity?id=
//            GET /api/v1/opensanctions/stats
app.route('/api/v1', opensanctionsRouter);
app.route('/api/v1', cloakRouter);

// Dehash.lt — hash decryption / reverse lookup (md5/sha1/sha256/sha384/sha512).
// No API key required.
// Endpoint: GET /api/v1/dehash?hash=
app.route('/api/v1', dehashRouter);

// OpenCVE Cloud — enriched CVE records (vendors, CVSS, KEV, EPSS, CWE).
// Requires OPENCVE_API_TOKEN (free org token at app.opencve.io).
// Endpoint: GET /api/v1/opencve/cve/:id
app.route('/api/v1', opencveRouter);

// Darknet Intel Tools — GreyNoise, Pulsedive, Vulners, IntelX, AbuseIPDB,
// deep ransomware, HIBP, abuse.ch, OTX, Hybrid Analysis.
// Partially key-gated (see source-status endpoint for details).
app.route('/api/v1', darknetIntelRouter);

// (darkweb-osint routes registered before global auth — see public routes section above)

// FBI Wanted — search the FBI wanted persons database.
// No API key required (public government API).
// Endpoints: GET /api/v1/fbi-wanted/search?q=
//            GET /api/v1/fbi-wanted/list?page=&pageSize=&field_office=
app.route('/api/v1', fbiWantedRouter);

// Interpol Red Notices — search INTERPOL's wanted persons database.
// No API key required (public government API).
// Endpoints: GET /api/v1/interpol/red-notices?name=&forename=&nationality=
//            GET /api/v1/interpol/red-notices/:noticeId
app.route('/api/v1', interpolRouter);

// Mozilla TLS Observatory — TLS/SSL configuration scanning.
// No API key required (public Mozilla service).
// Endpoints: GET /api/v1/mozilla-tls/scan?url=
//            GET /api/v1/mozilla-tls/result?scanId=
app.route('/api/v1', mozillaTlsRouter);

// Virushee — file hash multi-engine AV scanning.
// No API key required (public API).
// Endpoint: GET /api/v1/virushee/check?hash=
app.route('/api/v1', virusheeRouter);

// Tools Directory — curated catalog of 50+ offensive and defensive security tools.
// Data ships in public/data/tools/ built by scripts/build-tools-manifest.mjs.
app.route('/api/v1', toolsRouter);

// ── Weekly TI Dashboard (RSS articles + supply chain incidents + LLM enrichment) ──
import { tiDashboardRouter } from './routes/ti-dashboard';
app.route('/api/v1', tiDashboardRouter);

// ── DNS Lookup (dnsx-inspired multi-record resolution + CDN/ASN/wildcard detection) ──
import { dnsLookupRouter } from './routes/dns-lookup';
app.route('/api/v1', dnsLookupRouter);

// ── Tool Chain Agent (CyberSentinel-inspired deterministic investigation workflows) ──
import { toolChainRouter } from './routes/tool-chain';
app.route('/api/v1', toolChainRouter);

// ── Knowledge Graph (TI data → ReactFlow visualization) ──
import { knowledgeGraphRouter } from './routes/knowledge-graph';
app.route('/api/v1', knowledgeGraphRouter);
// ── FlowViz (edge port of davidljohnson/flowviz, MIT) + Procedure extraction
// (edge port of netandneedle/procedure-extraction-pipeline, Apache-2.0) ──
app.route('/api/v1', flowvizRouter);
app.route('/api/v1', proceduresRouter);
// ── CTI Collector (VHunt-inspired IOC fusion + AI prediction + mutation) ──
import {
  ctiCollectHandler,
  ctiStatsHandler,
  ctiIocsHandler,
  ctiNewsHandler,
  ctiPredictionsGetHandler,
  ctiPredictionsPostHandler,
  ctiMutateHandler,
  ctiMutationsHandler,
  ctiDecayHandler,
  ctiSweepHandler,
} from './routes/cti-collector';
app.post('/api/v1/cti/collect', ctiCollectHandler);
app.get('/api/v1/cti/stats', ctiStatsHandler);
app.get('/api/v1/cti/iocs', ctiIocsHandler);
app.get('/api/v1/cti/news', ctiNewsHandler);
app.get('/api/v1/cti/predictions', ctiPredictionsGetHandler);
app.post('/api/v1/cti/predictions', ctiPredictionsPostHandler);
app.post('/api/v1/cti/mutate', ctiMutateHandler);
app.get('/api/v1/cti/mutations', ctiMutationsHandler);
app.post('/api/v1/cti/decay', ctiDecayHandler);
app.post('/api/v1/cti/sweep', ctiSweepHandler);

/* ─── CTI Workspaces (AEAD Lifecycle) ─────────────────────────────── */
app.get('/api/v1/workspaces', listWorkspacesHandler);
app.post('/api/v1/workspaces', createWorkspaceHandler);
app.get('/api/v1/workspaces/:id', getWorkspaceHandler);
app.put('/api/v1/workspaces/:id', updateWorkspaceHandler);
app.delete('/api/v1/workspaces/:id', deleteWorkspaceHandler);
app.get('/api/v1/workspaces/:id/subjects', listSubjectsHandler);
app.post('/api/v1/workspaces/:id/subjects', createSubjectHandler);
app.get('/api/v1/workspaces/:id/connections', listConnectionsHandler);
app.post('/api/v1/workspaces/:id/connections', createConnectionHandler);
app.get('/api/v1/workspaces/:id/findings', listFindingsHandler);
app.post('/api/v1/workspaces/:id/findings', createFindingHandler);
app.get('/api/v1/workspaces/:id/timeline', listTimelineHandler);
app.post('/api/v1/workspaces/:id/timeline', addTimelineHandler);
app.get('/api/v1/workspaces/:id/workflow', workflowStateHandler);
app.post('/api/v1/workspaces/:id/workflow/advance', workflowAdvanceHandler);
app.get('/api/v1/workspaces/:id/workflow/summary', workflowSummaryHandler);
app.get('/api/v1/workspaces/:id/export', exportWorkspaceHandler);
/* ─── CTI Exposure & Export ──────────────────────────────────────── */
app.post('/api/v1/cti/exposure', exposureScoreHandler);
app.post('/api/v1/cti/export/stix', exportStixCtiHandler);
app.post('/api/v1/cti/render/graph', renderGraphHandler);

/* ─── Telegram Intelligence Search (TraceOn-inspired) ───────────── */
import {
  tgBooleanSearchHandler,
  tgTimelineHandler,
  tgSavedSearchesListHandler,
  tgSavedSearchCreateHandler,
  tgSavedSearchDeleteHandler,
} from './routes/tg-intelligence-search';

app.get('/api/v1/tg-search', tgBooleanSearchHandler);
app.get('/api/v1/tg-timeline', tgTimelineHandler);
app.get('/api/v1/tg-saved-searches', tgSavedSearchesListHandler);
app.post('/api/v1/tg-saved-searches', tgSavedSearchCreateHandler);
app.delete('/api/v1/tg-saved-searches/:id', tgSavedSearchDeleteHandler);

/* ─── SOCRadar-inspired Tools ───────────────────────────────────── */
import { ddosDashboardHandler, ddosBotnetLookupHandler, ddosIocFeedHandler } from './routes/ddos-intelligence';
import { fortibleedCheckHandler, fortibleedBatchHandler } from './routes/fortibleed-check';
import { healthBreachDashboardHandler, healthBreachSearchHandler } from './routes/health-breach-tracker';
import {
  threatReportOverviewHandler,
  threatReportCountryHandler,
  threatReportIndustryHandler,
  threatReportExternalHandler,
} from './routes/threat-reports';
import { analyticsReportHandler } from './routes/analytics-report';

import { emailOsnitProfileHandler, emailOsnitBulkHandler } from './routes/email-osnit-profile';
import { emailRegistrationHandler, emailRegistrationPlatformsHandler } from './routes/email-registration';

app.get('/api/v1/ddos/dashboard', ddosDashboardHandler);
app.get('/api/v1/ddos/botnet-lookup', ddosBotnetLookupHandler);
app.get('/api/v1/ddos/ioc-feed', ddosIocFeedHandler);
app.get('/api/v1/fortibleed/check', fortibleedCheckHandler);
app.post('/api/v1/fortibleed/batch', fortibleedBatchHandler);
app.get('/api/v1/health-breach/dashboard', healthBreachDashboardHandler);
app.get('/api/v1/health-breach/search', healthBreachSearchHandler);
app.post('/api/v1/analytics-report', analyticsReportHandler);
app.get('/api/v1/threat-reports', threatReportOverviewHandler);
app.get('/api/v1/threat-reports/country', threatReportCountryHandler);
app.get('/api/v1/threat-reports/industry', threatReportIndustryHandler);
app.get('/api/v1/threat-reports/external', threatReportExternalHandler);

app.get('/api/v1/email-osnit/profile', emailOsnitProfileHandler);
app.post('/api/v1/email-osnit/bulk', emailOsnitBulkHandler);
app.get('/api/v1/email-registration', emailRegistrationHandler);
app.get('/api/v1/email-registration/platforms', emailRegistrationPlatformsHandler);

// Estate Configuration & Alert Feed (noise-to-signal foundation)
app.route('/api/v1/estate', estateRoutes);

// User authentication & organization management
import authRoutes from './routes/auth';
import orgRoutes from './routes/orgs';
import leaderboardRoutes from './routes/leaderboard';
app.route('/api/v1/auth', authRoutes);
app.route('/api/v1/orgs', orgRoutes);
app.route('/api/v1/leaderboard', leaderboardRoutes);

// One-Time Secret — encrypted secret sharing with burn-after-reading
import { createSecretHandler, getSecretHandler } from './routes/one-time-secret';
app.post('/api/v1/one-time-secret', createSecretHandler);
app.get('/api/v1/one-time-secret/:id', getSecretHandler);

// Threat Intelligence vertical routes
import tiFeedAggregateRoutes from './routes/ti-feed-aggregate';
import tiAsmRoutes from './routes/ti-asm';
import tiAiAnalysisRoutes from './routes/ti-ai-analysis';
app.route('/api/v1/ti', tiFeedAggregateRoutes);
app.route('/api/v1/ti', tiAsmRoutes);
app.route('/api/v1/ti', tiAiAnalysisRoutes);

// ── Metabigor-equivalent OSINT routes (free, no API key) ──────────
import { certTransparencyHandler } from './routes/cert-transparency';
import { cdnDetectHandler } from './routes/cdn-detect';
import { cidrLookupHandler } from './routes/cidr-lookup';
app.get('/api/v1/cert-transparency', certTransparencyHandler);
app.get('/api/v1/cdn-detect', cdnDetectHandler);
app.get('/api/v1/cidr-lookup', cidrLookupHandler);

// Cerast Intelligence — free OSINT domain exposure search
import { cerastRouter } from './routes/cerast';
app.route('/api/v1', cerastRouter);

// ThreatMon IntelHub — infostealer investigation (stealer log search by domain)
import { threatmonInfostealerRouter } from './routes/threatmon-infostealer';
app.route('/api/v1', threatmonInfostealerRouter);

// CVE Risk Matrix — CVSS × EPSS × KEV × recency quadrant scoring
import { cveRiskMatrixHandler } from './routes/cve-risk-matrix';
app.get('/api/v1/cve/risk-matrix', cveRiskMatrixHandler);

// Frameworks — TID-CMM (8 domains, 58 sub-caps) + UTIOM (7 phases, 3 pillars)
// CC-BY / CC BY-SA, replicated as static JSON in public/data/frameworks/
import { frameworksRouter } from './routes/frameworks';
app.route('/api/v1', frameworksRouter);

// Toolkit verticals — DFIR reference, GRC, SIEM library, hunting hypotheses,
// cloud reference, post-quantum crypto (all read-only, ASSETS-backed manifests)
app.route('/api/v1', dfirRefRouter);
app.route('/api/v1', grcRouter);
app.route('/api/v1', siemLibraryRouter);
app.route('/api/v1', huntHypothesesRouter);
app.route('/api/v1', observableExtractRouter);
app.route('/api/v1', fileTriageRouter);
app.route('/api/v1', ruleValidatorRouter);
app.route('/api/v1', netAnalyticsRouter);
app.route('/api/v1', velociraptorRouter);
app.route('/api/v1', sampleSubmissionRouter);
app.route('/api/v1', cloudRefRouter);
app.route('/api/v1', pqcRouter);

// Detection Wiki — 15,957 rules, ATT&CK matrix, Windows catalog (103k events), Security-Auditing (426), labs
app.route('/api/v1', detectionWikiRouter);

// Standardized 404 shape: matches the api-error contract ({ error, message })
// so clients get a human-readable message, not just a bare error code.
app.notFound((c) => c.json({ error: 'not_found', message: 'route not found' }, 404));

app.onError(errorHandler);

export default app;
