import { Suspense, useEffect, lazy, useMemo, type ComponentType } from 'react';
import {
  BrowserRouter,
  Routes,
  Route,
  useLocation,
  useNavigationType,
  Navigate,
  useSearchParams,
} from 'react-router-dom';
import { useTheme, useScrollProgress } from './hooks';
import { navLinks, personalInfo, stats, toolsNavLinks, TOOLS_NAV_BY_HOST } from './data/content';
import { currentSurface, SurfaceContext, useSurface, TOOL_HOSTS_BY_PATH, type Surface } from './lib/surface';
import { Header } from './components/Header';
import { Footer } from './components/Footer';
import { SkipToContent } from './components/SkipToContent';
import { StructuredData } from './components/StructuredData';
import { ScrollProgress } from './components/ui/ScrollProgress';
import { TabLoader } from './components/ui/TabLoader';
import { BackToTop } from './components/ui/BackToTop';
import { Layout } from './components/Layout';
import { AppShell } from './components/AppShell';
import { BackgroundLayer } from './components/BackgroundLayer';
import { LazyRoute } from './components/LazyRoute';
import { FeaturesProvider } from './components/FeaturesProvider';
import { McpProvider } from './components/ti-mindmap-mcp/McpContext';
import { CommandPaletteGate } from './components/CommandPaletteGate';

// Note (2026-05-12): tried React.lazy on these four shell components to
// trim the entry chunk. Lighthouse showed desktop wiki regressed 77→71
// and exif 84→71 because each new chunk adds a network round-trip that
// outweighs the parse savings. Keeping them eager.

// Top-level pages are lazy-loaded so the initial paint only ships the JS
// needed for the current route. Home stays eagerly imported because it's
// the most-likely landing page - lighthouse measurement 2026-05-12 showed
// lazy-Home regressed wiki score 77→64 and root 72→69. The Suspense
// fallback shifts FCP and adds CLS that outweighs the parse savings.
import Home from './pages/Home';
import ToolsHome from './pages/tools/ToolsHome';
const About = lazy(() => import('./pages/About'));
const Skills = lazy(() => import('./pages/Skills'));
const Experience = lazy(() => import('./pages/Experience'));
const McpCatalog = lazy(() => import('./pages/McpCatalog'));
const Status = lazy(() => import('./pages/Status'));
const DailyBriefs = lazy(() => import('./pages/DailyBriefs'));
const WebamonDtb = lazy(() => import('./pages/WebamonDtb'));
const PcMedicalist = lazy(() => import('./pages/threatintel/PcMedicalist'));
const AIThreats = lazy(() => import('./pages/AIThreats'));
const OssFeeds = lazy(() => import('./pages/OssFeeds'));
const WinReg = lazy(() => import('./pages/WinReg'));
const DfirRef = lazy(() => import('./pages/DfirRef'));
const GrcChecklists = lazy(() => import('./pages/GrcChecklists'));
const SiemLibrary = lazy(() => import('./pages/SiemLibrary'));
const HuntHypotheses = lazy(() => import('./pages/HuntHypotheses'));
const CloudReference = lazy(() => import('./pages/CloudReference'));
const Pqc = lazy(() => import('./pages/Pqc'));
const Cloak = lazy(() => import('./pages/Cloak'));
const CveRiskMatrix = lazy(() => import('./pages/CveRiskMatrix'));
const CoCGenerator = lazy(() => import('./pages/dfir/CoCGenerator'));
const SocCalculators = lazy(() => import('./pages/dfir/SocCalculators'));
const SysmonConfig = lazy(() => import('./pages/dfir/SysmonConfig'));
const HexWorkbench = lazy(() => import('./pages/dfir/HexWorkbench'));
const DfirConsole = lazy(() => import('./pages/dfir/DfirConsole'));
const ShareReportView = lazy(() => import('./pages/share/ShareReportView'));
const SigBase = lazy(() => import('./pages/SigBase'));
const Traceix = lazy(() => import('./pages/Traceix'));
const NhiScan = lazy(() => import('./pages/NhiScan'));
const UrlRisk = lazy(() => import('./pages/dfir/UrlRisk'));
const Whoxy = lazy(() => import('./pages/Whoxy'));
const IntelXPage = lazy(() => import('./pages/IntelX'));
const TruecallerPage = lazy(() => import('./pages/Truecaller'));
const Cerast = lazy(() => import('./pages/threatintel/Cerast'));
const ThreatMonInfostealer = lazy(() => import('./pages/threatintel/ThreatMonInfostealer'));
const Projects = lazy(() => import('./pages/Projects'));
const CaseStudy = lazy(() => import('./pages/CaseStudy'));
const ResearchPostPage = lazy(() => import('./pages/threatintel/ResearchPost'));
const DFIR = lazy(() => import('./pages/DFIR'));

const Phishing = lazy(() => import('./pages/dfir/Phishing'));
const Exposure = lazy(() => import('./pages/dfir/Exposure'));
const AssetIntel = lazy(() => import('./pages/dfir/AssetIntel'));
const WikiArticle = lazy(() => import('./pages/dfir/WikiArticle'));
const ActorDetail = lazy(() => import('./pages/dfir/ActorDetail'));
const Briefings = lazy(() => import('./pages/dfir/Briefings'));
const BriefingDetail = lazy(() => import('./pages/dfir/BriefingDetail'));
const Cve = lazy(() => import('./pages/dfir/Cve'));
const CodecHub = lazy(() => import('./pages/dfir/CodecHub'));
const IamHub = lazy(() => import('./pages/dfir/IamHub'));
const ImageIntel = lazy(() => import('./pages/dfir/ImageIntel'));
const PhoneHub = lazy(() => import('./pages/dfir/PhoneHub'));
const AgentSuite = lazy(() => import('./pages/dfir/AgentSuite'));
const StixHub = lazy(() => import('./pages/threatintel/StixHub'));
const RansomwareHub = lazy(() => import('./pages/threatintel/RansomwareHub'));
const ExposureCheck = lazy(() => import('./pages/threatintel/Exposure'));
const RansomwareGroups = lazy(() => import('./pages/threatintel/RansomwareGroups'));
const AiEscape = lazy(() => import('./pages/threatintel/AiEscape'));
const AiSecurityHub = lazy(() => import('./pages/threatintel/AiSecurityHub'));
const AiIncidents = lazy(() => import('./pages/threatintel/AiIncidents'));
const AiSecurityMatrix = lazy(() => import('./pages/threatintel/AiSecurityMatrix'));
const AiVulns = lazy(() => import('./pages/threatintel/AiVulns'));
const AiAdvisories = lazy(() => import('./pages/threatintel/AiAdvisories'));
const Cairn = lazy(() => import('./pages/threatintel/Cairn'));
const Nova = lazy(() => import('./pages/threatintel/Nova'));
const Denali = lazy(() => import('./pages/threatintel/Denali'));
const AiSecurityPlaybook = lazy(() => import('./pages/threatintel/AiSecurityPlaybook'));
const CertSearch = lazy(() => import('./pages/dfir/CertSearch'));
const AsnLookup = lazy(() => import('./pages/dfir/AsnLookup'));
const HostGraph = lazy(() => import('./pages/dfir/HostGraph'));
const Breach = lazy(() => import('./pages/dfir/Breach'));
const ExifParse = lazy(() => import('./pages/dfir/ExifParse'));
const ExposedHostPage = lazy(() => import('./pages/dfir/ExposedHost'));
const UrlPreview = lazy(() => import('./pages/dfir/UrlPreview'));
const IocExtractor = lazy(() => import('./pages/dfir/IocExtractor'));
const JwtInspect = lazy(() => import('./pages/dfir/JwtInspect'));
const GoogleDorks = lazy(() => import('./pages/dfir/GoogleDorks'));
const ZeroTrustAiAgents = lazy(() => import('./pages/dfir/ZeroTrustAiAgents'));
const SecurityGroupAnalyzer = lazy(() => import('./pages/dfir/SecurityGroupAnalyzer'));
const CloudTrailTriage = lazy(() => import('./pages/dfir/CloudTrailTriage'));
const CvePrioritizer = lazy(() => import('./pages/dfir/CvePrioritizer'));
const FusionExposure = lazy(() => import('./pages/dfir/FusionExposure'));
const EstateWatch = lazy(() => import('./pages/dfir/EstateWatch'));
const RiskRegister = lazy(() => import('./pages/dfir/RiskRegister'));
const AttackPathGraph = lazy(() => import('./pages/dfir/AttackPathGraph'));
const GrcEvidence = lazy(() => import('./pages/dfir/GrcEvidence'));
const VulnerabilityOps = lazy(() => import('./pages/dfir/VulnerabilityOps'));
const RansomwareQuant = lazy(() => import('./pages/dfir/RansomwareQuant'));
const PatchTaskMgr = lazy(() => import('./pages/dfir/PatchTaskMgr'));
const SocAutomation = lazy(() => import('./pages/dfir/SocAutomation'));
const RuleConverter = lazy(() => import('./pages/dfir/RuleConverter'));
const LinuxTriage = lazy(() => import('./pages/dfir/LinuxTriage'));
const TerraformScanner = lazy(() => import('./pages/dfir/TerraformScanner'));
const OpenApiAuditor = lazy(() => import('./pages/dfir/OpenApiAuditor'));
const SecHeadersLive = lazy(() => import('./pages/dfir/SecHeadersLive'));
const SecretScanner = lazy(() => import('./pages/dfir/SecretScanner'));
const GraphqlAuditor = lazy(() => import('./pages/dfir/GraphqlAuditor'));
const OsvScanner = lazy(() => import('./pages/dfir/OsvScanner'));
const Punycode = lazy(() => import('./pages/dfir/Punycode'));
const StixBuilder = lazy(() => import('./pages/dfir/StixBuilder'));
const Owasp = lazy(() => import('./pages/dfir/Owasp'));
const PromptInjection = lazy(() => import('./pages/dfir/PromptInjection'));
const PiTaxonomy = lazy(() => import('./pages/dfir/PiTaxonomy'));
const McpAudit = lazy(() => import('./pages/dfir/McpAudit'));
const KillChain = lazy(() => import('./pages/dfir/KillChain'));
const Diamond = lazy(() => import('./pages/dfir/Diamond'));
const Lolbins = lazy(() => import('./pages/dfir/Lolbins'));
const Lots = lazy(() => import('./pages/dfir/Lots'));
const Malapi = lazy(() => import('./pages/dfir/Malapi'));
const Car = lazy(() => import('./pages/dfir/Car'));
const Capec = lazy(() => import('./pages/dfir/Capec'));
const Hijacklibs = lazy(() => import('./pages/dfir/Hijacklibs'));
const Veris = lazy(() => import('./pages/dfir/Veris'));
const Engage = lazy(() => import('./pages/dfir/Engage'));
const ReportHub = lazy(() => import('./pages/dfir/ReportHub'));
const CtMonitor = lazy(() => import('./pages/dfir/CtMonitor'));
const StealerParser = lazy(() => import('./pages/dfir/StealerParser'));
const ThreatGraph = lazy(() => import('./pages/dfir/ThreatGraph'));
const AttackNavigator = lazy(() => import('./pages/dfir/AttackNavigator'));
const IrPlaybooks = lazy(() => import('./pages/dfir/IrPlaybooks'));
const EmailDefense = lazy(() => import('./pages/dfir/EmailDefense'));
const Nhi = lazy(() => import('./pages/dfir/Nhi'));
const Pivex = lazy(() => import('./pages/dfir/Pivex'));
const CryptoTracer = lazy(() => import('./pages/dfir/CryptoTracer'));
const PowershellDeobf = lazy(() => import('./pages/dfir/PowershellDeobf'));
const PowershellAnalyzer = lazy(() => import('./pages/dfir/PowershellAnalyzer'));
const InvestigationHistory = lazy(() => import('./pages/threatintel/InvestigationHistory'));
const DetectionChokepointsHub = lazy(() => import('./pages/dfir/DetectionChokepointsHub'));
const Grc = lazy(() => import('./pages/dfir/Grc'));
const DlpScan = lazy(() => import('./pages/dfir/DlpScan'));
const DataClassification = lazy(() => import('./pages/dfir/DataClassification'));
const PrivacyHub = lazy(() => import('./pages/dfir/PrivacyHub'));
const UsernameInvestigator = lazy(() => import('./pages/dfir/UsernameInvestigator'));
const DomainInvestigator = lazy(() => import('./pages/dfir/DomainInvestigator'));
const PassiveDns = lazy(() => import('./pages/dfir/PassiveDns'));
const MalwareAnalyzer = lazy(() => import('./pages/dfir/MalwareAnalyzer'));
const Notebooks = lazy(() => import('./pages/dfir/Notebooks'));
const VulnToolkitCatalog = lazy(() => import('./pages/dfir/VulnToolkitCatalog'));
const IocInvestigate = lazy(() => import('./pages/dfir/IocInvestigate'));
const DfirCopilotPage = lazy(() => import('./pages/dfir/DfirCopilot'));
const YaraWorkbench = lazy(() => import('./pages/dfir/YaraWorkbench'));
const StixWorkbench = lazy(() => import('./pages/dfir/StixWorkbench'));
const WifiInvestigation = lazy(() => import('./pages/dfir/WifiInvestigation'));
const Wayback = lazy(() => import('./pages/dfir/Wayback'));
const LogParser = lazy(() => import('./pages/dfir/LogParser'));
const Blocklists = lazy(() => import('./pages/dfir/Blocklists'));
const MedusaScanner = lazy(() => import('./pages/dfir/MedusaScanner'));
const CsrfPocGenerator = lazy(() => import('./pages/dfir/CsrfPocGenerator'));
const XssPayloadSelector = lazy(() => import('./pages/dfir/XssPayloadSelector'));
const TidCmm = lazy(() => import('./pages/dfir/TidCmm'));
const Utiom = lazy(() => import('./pages/dfir/Utiom'));

const Socmint = lazy(() => import('./pages/dfir/Socmint'));
const OsintMapper = lazy(() => import('./pages/dfir/OsintMapper'));
const TimestampConverter = lazy(() => import('./pages/dfir/TimestampConverter'));
const HashCalculator = lazy(() => import('./pages/dfir/HashCalculator'));
const BrandImpersonation = lazy(() => import('./pages/dfir/BrandImpersonation'));
const PlistProtobuf = lazy(() => import('./pages/dfir/PlistProtobuf'));
const PcapTriage = lazy(() => import('./pages/dfir/PcapTriage'));
const RegistryHive = lazy(() => import('./pages/dfir/RegistryHive'));
const EvtxParser = lazy(() => import('./pages/dfir/EvtxParser'));
const SqliteExplorer = lazy(() => import('./pages/dfir/SqliteExplorer'));
const IosBackupExplorer = lazy(() => import('./pages/dfir/IosBackupExplorer'));
const WebLogAnalyzer = lazy(() => import('./pages/dfir/WebLogAnalyzer'));
const PrefetchAnalyzer = lazy(() => import('./pages/dfir/PrefetchAnalyzer'));
const ProcedureExtract = lazy(() => import('./pages/dfir/ProcedureExtract'));
const SubdomainTakeover = lazy(() => import('./pages/dfir/SubdomainTakeover'));

const AiSuite = lazy(() => import('./pages/dfir/AiSuite'));
const EmlExtractor = lazy(() => import('./pages/dfir/EmlExtractor'));
const ThreatIntelHome = lazy(() => import('./pages/threatintel/Home'));
const ThreatIntelAbout = lazy(() => import('./pages/threatintel/About'));
const ThreatIntelCatalog = lazy(() => import('./pages/threatintel/Catalog'));
const LiveCenter = lazy(() => import('./pages/threatintel/LiveCenter'));
const LiveFeed = lazy(() => import('./pages/threatintel/LiveFeed'));
const CveDetail = lazy(() => import('./pages/threatintel/CveDetail'));
const TelegramHub = lazy(() => import('./pages/threatintel/TelegramHub'));
const SourceHealth = lazy(() => import('./pages/threatintel/SourceHealth'));
const SocDashboard = lazy(() => import('./pages/threatintel/SocDashboard'));
// ── Threat Intel: direct page components (auto-added by audit) ──
const ACH = lazy(() => import('./pages/threatintel/ACH'));
const AIReportShowcase = lazy(() => import('./pages/threatintel/AIReportShowcase'));
const AgenticReports = lazy(() => import('./pages/threatintel/AgenticReports'));

const AttackFlowLibrary = lazy(() => import('./pages/threatintel/AttackFlowLibrary'));
const Attribution = lazy(() => import('./pages/threatintel/AttributionFramework'));
const AwesomeLists = lazy(() => import('./pages/dfir/AwesomeLists'));
const C2Tracker = lazy(() => import('./pages/threatintel/C2Tracker'));
const CertStreamLive = lazy(() => import('./pages/threatintel/CertStreamLive'));
const CloudThreatLandscape = lazy(() => import('./pages/threatintel/CloudThreatLandscape'));
const Copilot = lazy(() => import('./pages/threatintel/Copilot'));
const CryptoScamFeed = lazy(() => import('./pages/threatintel/CryptoScamFeed'));
const CuratedToolbox = lazy(() => import('./pages/threatintel/CuratedToolbox'));
const CuratedCerts = lazy(() => import('./pages/threatintel/CuratedCerts'));
const ToolsDirectory = lazy(() => import('./pages/threatintel/ToolsDirectory'));
const OsintDirectory = lazy(() => import('./pages/threatintel/OsintDirectory'));
const CtiBookmarks = lazy(() => import('./pages/threatintel/CtiBookmarks'));
const CveIntel = lazy(() => import('./pages/threatintel/CveIntel'));
const CveResourcesCatalog = lazy(() => import('./pages/dfir/CveResourcesCatalog'));
const CyberCrime = lazy(() => import('./pages/threatintel/CyberCrime'));
const DarkWeb = lazy(() => import('./pages/threatintel/DarkWebOsintTools'));
const DarkWebRecon = lazy(() => import('./pages/threatintel/DarkWebRecon'));
const DarkWebPlaybook = lazy(() => import('./pages/threatintel/DarkWebPlaybook'));
const DarknetIntel = lazy(() => import('./pages/DarknetIntel'));
const OnionWatch = lazy(() => import('./pages/dfir/OnionWatch'));
const DarknetMarketsTimeline = lazy(() => import('./pages/threatintel/DarknetMarketsTimeline'));
const DarknetList = lazy(() => import('./pages/threatintel/DarknetList'));
const DeepDarkCTI = lazy(() => import('./pages/threatintel/DeepDarkCTI'));
const Detections = lazy(() => import('./pages/threatintel/Detections'));
const DetectionWiki = lazy(() => import('./pages/threatintel/DetectionWiki'));
const ThreatActorMonitor = lazy(() => import('./pages/threatintel/ThreatActorMonitor'));
const DisarmFramework = lazy(() => import('./pages/threatintel/DisarmFramework'));
const DomainMonitor = lazy(() => import('./pages/threatintel/DomainMonitor'));
const EntityResolution = lazy(() => import('./pages/threatintel/EntityResolution'));
const ExternalResources = lazy(() => import('./pages/threatintel/ExternalResources'));
const F3ead = lazy(() => import('./pages/threatintel/F3ead'));
const F2t2ea = lazy(() => import('./pages/threatintel/F2t2ea'));
const Ooda = lazy(() => import('./pages/threatintel/Ooda'));
const ThreatLedDefence = lazy(() => import('./pages/threatintel/ThreatLedDefence'));
const KillChainV2 = lazy(() => import('./pages/threatintel/KillChainV2'));
const UnifiedKillChain = lazy(() => import('./pages/threatintel/UnifiedKillChain'));
const FeedCatalog = lazy(() => import('./pages/threatintel/FeedCatalog'));
const FeedQuality = lazy(() => import('./pages/threatintel/FeedQuality'));
const FeedScheduler = lazy(() => import('./pages/threatintel/FeedScheduler'));
const FeedSources = lazy(() => import('./pages/threatintel/FeedSources'));
const ThreatClusterFeeds = lazy(() => import('./pages/threatintel/ThreatCluster'));
const ThreaticonFeeds = lazy(() => import('./pages/threatintel/Threaticon'));
const DphishFeeds = lazy(() => import('./pages/threatintel/Dphish'));
const DestroylistFeeds = lazy(() => import('./pages/threatintel/Destroylist'));
const LivingThreatFeeds = lazy(() => import('./pages/threatintel/LivingThreat'));
const MalwareAnalyzerFeeds = lazy(() => import('./pages/threatintel/MalwareAnalyzer'));
const ThreatClusterEntities = lazy(() => import('./pages/threatintel/ThreatClusterEntities'));
const FlowViz = lazy(() => import('./pages/threatintel/FlowViz'));

const GithubAdvisories = lazy(() => import('./pages/threatintel/GithubAdvisories'));
const GlobalPulse = lazy(() => import('./pages/threatintel/GlobalPulse'));
const Infostealer = lazy(() => import('./pages/threatintel/Infostealer'));
const InfraIntel = lazy(() => import('./pages/threatintel/InfraIntel'));
const InsiderThreatMatrix = lazy(() => import('./pages/threatintel/InsiderThreatMatrix'));
const IntelDashboard = lazy(() => import('./pages/threatintel/IntelDashboard'));
const IocCorrelation = lazy(() => import('./pages/threatintel/IocCorrelation'));
const IocEnrichment = lazy(() => import('./pages/threatintel/IocEnrichment'));
const IocFeedsPage = lazy(() => import('./pages/threatintel/IocFeedsPage'));
const KnowledgeGraph = lazy(() => import('./pages/threatintel/KnowledgeGraph'));
const LiveIocs = lazy(() => import('./pages/threatintel/LiveIocs'));
const LlmThreatAtlas = lazy(() => import('./pages/threatintel/LlmThreatAtlas'));
const MalpediaPage = lazy(() => import('./pages/threatintel/MalpediaPage'));
const MaltrailTrails = lazy(() => import('./pages/threatintel/MaltrailTrails'));
const MalwareIocs = lazy(() => import('./pages/threatintel/MalwareIocs'));
const MalwareSandbox = lazy(() => import('./pages/threatintel/MalwareSandbox'));
const McpSearch = lazy(() => import('./pages/threatintel/McpSearch'));
const Metrics = lazy(() => import('./pages/threatintel/Metrics'));
const MitreMatrix = lazy(() => import('./pages/dfir/MitreMatrix'));
const MyThreatIntel = lazy(() => import('./pages/threatintel/MyThreatIntel'));
const OsintCliTools = lazy(() => import('./pages/threatintel/OsintCliTools'));
const OsintCountryMap = lazy(() => import('./pages/threatintel/OsintCountryMap'));
const OsintFramework = lazy(() => import('./pages/dfir/OsintFramework'));
const OwaspAiLandscape = lazy(() => import('./pages/threatintel/OwaspAiLandscape'));
const PhishFeed = lazy(() => import('./pages/threatintel/PhishFeed'));
const PhishingWordlists = lazy(() => import('./pages/threatintel/PhishingWordlists'));
const Predictions = lazy(() => import('./pages/threatintel/Predictions'));
const PredictiveIntel = lazy(() => import('./pages/threatintel/PredictiveIntel'));
const RedHuntInsights = lazy(() => import('./pages/threatintel/RedHuntInsights'));
const RedHuntLabsResearch = lazy(() => import('./pages/threatintel/RedHuntLabsResearch'));

const Reports = lazy(() => import('./pages/threatintel/ThreatIntelReports'));
const ResearchSignal = lazy(() => import('./pages/threatintel/Signal'));
const ScamWatch = lazy(() => import('./pages/dfir/ScamWatch'));
const SecopsCatalog = lazy(() => import('./pages/dfir/SecopsCatalog'));
const SecretLeaks = lazy(() => import('./pages/threatintel/SecretLeaks'));

const SocialFirehose = lazy(() => import('./pages/threatintel/SocialFirehose'));

const ThreatLandscapeStix = lazy(() => import('./pages/threatintel/ThreatLandscapeStix'));
const EntityGraphPage = lazy(() => import('./pages/threatintel/EntityGraphPage'));
const TechAiNews = lazy(() => import('./pages/dfir/TechAiNews'));

const ActorHub = lazy(() => import('./pages/threatintel/ActorHub'));
const BreachHub = lazy(() => import('./pages/threatintel/BreachHub'));
const SupplyChainHub = lazy(() => import('./pages/threatintel/SupplyChainHub'));
const ThreatFeeds = lazy(() => import('./pages/dfir/ThreatFeeds'));
const ThreatMap = lazy(() => import('./pages/dfir/ThreatMap'));
const ThreatPulse = lazy(() => import('./pages/threatintel/ThreatPulse'));
const ThreatSignalRss = lazy(() => import('./pages/threatintel/ThreatSignalRss'));
const UnifiedSearch = lazy(() => import('./pages/threatintel/UnifiedSearch'));
const VolexityThreatIntel = lazy(() => import('./pages/threatintel/VolexityThreatIntel'));
const TgIntelSearch = lazy(() => import('./pages/threatintel/TgIntelSearch'));
const SocradarTools = lazy(() => import('./pages/threatintel/SocradarTools'));
const Webamon = lazy(() => import('./pages/threatintel/Webamon'));
const Wiki = lazy(() => import('./pages/dfir/Wiki'));
const Writeups = lazy(() => import('./pages/threatintel/Writeups'));

const YaraPage = lazy(() => import('./pages/threatintel/Yarahub'));

const NotFound = lazy(() => import('./pages/NotFound'));
const CampaignDetail = lazy(() => import('./pages/threatintel/CampaignDetail'));
const OrklPage = lazy(() => import('./pages/dfir/Orkl'));
const Blog = lazy(() => import('./pages/Blog'));
const BlogPost = lazy(() => import('./pages/BlogPost'));
const AdminApp = lazy(() => import('./pages/admin/AdminApp'));
const AdminAnalyticsDashboard = lazy(() => import('./pages/admin/AnalyticsDashboard'));
const AlertFeed = lazy(() => import('./pages/threatintel/AlertFeed'));
const VeraChat = lazy(() => import('./pages/threatintel/VeraChat'));
const RansomwareLive = lazy(() => import('./pages/threatintel/RansomwareLive'));
const CyberPulse = lazy(() => import('./pages/threatintel/CyberPulse'));
const AiHoneypotObservatory = lazy(() => import('./pages/threatintel/AiHoneypotObservatory'));
const AiLlmIntel = lazy(() => import('./pages/threatintel/AiLlmIntel'));
const WhoisHistory = lazy(() => import('./pages/dfir/WhoisHistory'));
const OpenDirectory = lazy(() => import('./pages/dfir/OpenDirectory'));
const ApkAnalyzer = lazy(() => import('./pages/dfir/ApkAnalyzer'));
const PgpTool = lazy(() => import('./pages/dfir/PgpTool'));
const OneTimeSecret = lazy(() => import('./pages/dfir/OneTimeSecret'));
const EmailReputation = lazy(() => import('./pages/dfir/EmailReputation'));
const EmailOsnit = lazy(() => import('./pages/dfir/EmailOsnit'));
const PhishOps = lazy(() => import('./pages/dfir/PhishOps'));
const PhishBook = lazy(() => import('./pages/dfir/PhishBook'));

// (removed LiveFeedsPage and MyDashboardPage)
const InfostealerDetail = lazy(() => import('./pages/threatintel/InfostealerDetail'));
const InfostealerIntel = lazy(() => import('./pages/dfir/InfostealerIntel'));
const DmarcAnalyzer = lazy(() => import('./pages/dfir/DmarcAnalyzer'));
const AssessmentDetail = lazy(() => import('./pages/threatintel/AssessmentDetail'));
const ExportHub = lazy(() => import('./pages/dfir/ExportHub'));
const Dnscope = lazy(() => import('./pages/dfir/Dnscope'));
const Tracerules = lazy(() => import('./pages/dfir/Tracerules'));
const DfirCatalog = lazy(() => import('./pages/dfir/Catalog'));

const Anarchy = lazy(() => import('./pages/Anarchy'));

const RadarHome = lazy(() => import('./pages/radar/Home'));
const RadarScanResults = lazy(() => import('./pages/radar/ScanResults'));
const ArgusPage = lazy(() => import('./pages/Argus'));

/**
 * /dfir/file?h=<hash> is the legacy entry point for the standalone hash
 * analyser. The page was merged into the IOC checker; this redirect rewrites
 * `?h=<hash>` to `?indicator=<hash>` so legacy bookmarks auto-populate the
 * input rather than landing on a blank form.
 */
function DfirFileRedirect() {
  const [params] = useSearchParams();
  // SSR: StaticRouter cannot handle <Navigate> on initial render — return null
  // and let the client hydrate then redirect.
  if (typeof window === 'undefined') return null;
  const hash = params.get('h');
  // Target /dfir/ioc-investigate directly. /dfir/ioc-check is itself a
  // preserveQuery redirect to /dfir/ioc-investigate, so routing through it
  // would chain two client-side redirects for every legacy /dfir/file link.
  const target = hash ? `/dfir/ioc-investigate?indicator=${encodeURIComponent(hash)}` : '/dfir/ioc-investigate';
  return <Navigate to={target} replace />;
}

/**
 * Redirect that preserves the query string. Used for alias routes whose
 * target page reads search params (e.g. `/dfir/ioc-check?indicator=…`
 * → `/dfir/ioc-investigate?indicator=…`). Without this, `<Navigate>`
 * drops the query string and the deep-link auto-run never fires.
 */
function QueryRedirect({ to }: { to: string }) {
  const [params] = useSearchParams();
  if (typeof window === 'undefined') return null;
  const qs = params.toString();
  const target = qs ? `${to}?${qs}` : to;
  return <Navigate to={target} replace />;
}

interface RouteDef {
  path: string;
  Component: ComponentType;
  /** Eager routes render directly; the rest wrap in <LazyRoute> for Suspense. */
  eager?: boolean;
}

/**
 * Data-driven route table - replaces ~1820 lines of repetitive <Route> JSX.
 * Route ORDER does not affect matching (React Router v6 ranks by path
 * specificity, not declaration order); entries are kept in the original source
 * order for diff sanity. Every lazy()/eager/redirect mapping is byte-identical
 * to the previous JSX, so chunk-splitting and the documented eager-Home
 * decision (Home stays eager) are preserved.
 */
const ROUTES: ReadonlyArray<RouteDef> = [
  { path: '/', Component: SurfaceHome, eager: true },
  { path: '/about', Component: About },
  { path: '/skills', Component: Skills },
  { path: '/experience', Component: Experience },
  { path: '/projects', Component: Projects },
  { path: '/projects/:slug', Component: CaseStudy },
  { path: '/share/report/:token', Component: ShareReportView },
  { path: '/blog', Component: Blog },
  { path: '/blog/c/:type', Component: Blog },
  { path: '/blog/t/:tag', Component: Blog },
  { path: '/blog/:slug', Component: BlogPost },
  { path: '/mcp', Component: McpCatalog },
  { path: '/status', Component: Status },
  { path: '/daily-briefs', Component: DailyBriefs },
  { path: '/threatintel/webamon-dtb', Component: WebamonDtb },
  { path: '/threatintel/pcmedicalist', Component: PcMedicalist },
  { path: '/dfir/ai-threats', Component: AIThreats },
  { path: '/dfir/oss-feeds', Component: OssFeeds },
  { path: '/dfir/winreg', Component: WinReg },
  { path: '/dfir/dfir-ref', Component: DfirRef },
  { path: '/dfir/grc-checklists', Component: GrcChecklists },
  { path: '/dfir/siem-library', Component: SiemLibrary },
  { path: '/dfir/hunt-hypotheses', Component: HuntHypotheses },
  { path: '/dfir/cloud-reference', Component: CloudReference },
  { path: '/dfir/pqc', Component: Pqc },
  { path: '/dfir/cloak', Component: Cloak },
  { path: '/dfir/cve-risk-matrix', Component: CveRiskMatrix },
  { path: '/dfir/coc-generator', Component: CoCGenerator },
  { path: '/dfir/soc-calculators', Component: SocCalculators },
  { path: '/dfir/sysmon-config', Component: SysmonConfig },
  { path: '/dfir/hex-workbench', Component: HexWorkbench },
  { path: '/dfir/console', Component: DfirConsole },
  { path: '/dfir/sigbase', Component: SigBase },
  { path: '/dfir/traceix', Component: Traceix },
  { path: '/dfir/nhi-scan', Component: NhiScan },
  { path: '/dfir/whoxy', Component: Whoxy },
  { path: '/dfir/intelx', Component: IntelXPage },
  { path: '/dfir/truecaller', Component: TruecallerPage },
  { path: '/threatintel/external/cerast', Component: Cerast },
  { path: '/threatintel/external/threatmon', Component: ThreatMonInfostealer },
  { path: '/dfir', Component: DFIR },
  { path: '/dfir/orkl', Component: OrklPage },
  { path: '/dfir/phishing', Component: Phishing },
  { path: '/dfir/whois-history', Component: WhoisHistory },
  { path: '/dfir/open-directory', Component: OpenDirectory },
  { path: '/dfir/exposure', Component: Exposure },
  { path: '/dfir/exposed-host', Component: ExposedHostPage },
  { path: '/dfir/estate', Component: EstateWatch },
  { path: '/dfir/asset-intel', Component: AssetIntel },
  { path: '/dfir/file', Component: DfirFileRedirect, eager: true },
  { path: '/threatintel/wiki/:slug', Component: WikiArticle },
  { path: '/threatintel/actors/:slug', Component: ActorDetail },
  { path: '/threatintel/briefings', Component: Briefings },
  { path: '/threatintel/briefings/:slug', Component: BriefingDetail },
  { path: '/dfir/cve', Component: Cve },
  { path: '/dfir/vuln-toolkit', Component: VulnToolkitCatalog },
  { path: '/dfir/codec', Component: CodecHub },
  { path: '/dfir/cert-search', Component: CertSearch },
  { path: '/dfir/asn', Component: AsnLookup },
  { path: '/dfir/iam-hub', Component: IamHub },
  { path: '/dfir/image-intel', Component: ImageIntel },
  { path: '/dfir/phone-hub', Component: PhoneHub },
  { path: '/dfir/host-graph', Component: HostGraph },
  { path: '/dfir/breach', Component: Breach },
  { path: '/dfir/exif', Component: ExifParse },
  { path: '/dfir/url-preview', Component: UrlPreview },
  { path: '/dfir/extract', Component: IocExtractor },
  { path: '/dfir/jwt', Component: JwtInspect },
  { path: '/dfir/google-dorks', Component: GoogleDorks },
  { path: '/dfir/zero-trust-ai-agents', Component: ZeroTrustAiAgents },
  { path: '/dfir/sg-analyzer', Component: SecurityGroupAnalyzer },
  { path: '/dfir/cloudtrail-triage', Component: CloudTrailTriage },
  { path: '/dfir/cve-prioritizer', Component: CvePrioritizer },
  { path: '/dfir/fusion-exposure', Component: FusionExposure },
  { path: '/dfir/risk-register', Component: RiskRegister },
  { path: '/dfir/attack-path', Component: AttackPathGraph },
  { path: '/dfir/grc-evidence', Component: GrcEvidence },
  { path: '/dfir/vulnerability-ops', Component: VulnerabilityOps },
  { path: '/dfir/ransomware-quant', Component: RansomwareQuant },
  { path: '/dfir/patch-task-mgr', Component: PatchTaskMgr },
  { path: '/dfir/soc-automation', Component: SocAutomation },
  { path: '/dfir/rule-converter', Component: RuleConverter },
  { path: '/dfir/linux-triage', Component: LinuxTriage },
  { path: '/dfir/terraform-scan', Component: TerraformScanner },
  { path: '/dfir/openapi-audit', Component: OpenApiAuditor },
  { path: '/dfir/sec-headers-live', Component: SecHeadersLive },
  { path: '/dfir/secret-scan', Component: SecretScanner },
  { path: '/dfir/medusa-scan', Component: MedusaScanner },
  { path: '/dfir/csrf-poc', Component: CsrfPocGenerator },
  { path: '/dfir/xss-payloads', Component: XssPayloadSelector },
  { path: '/dfir/graphql-audit', Component: GraphqlAuditor },
  { path: '/dfir/osv-scan', Component: OsvScanner },
  { path: '/dfir/punycode', Component: Punycode },
  { path: '/dfir/stix-builder/b/:bundleId', Component: StixBuilder },
  { path: '/threatintel/campaigns/:id', Component: CampaignDetail },
  { path: '/threatintel/telegram', Component: TelegramHub },
  { path: '/threatintel/source-health', Component: SourceHealth },
  { path: '/threatintel/soc-dashboard', Component: SocDashboard },
  { path: '/threatintel/research/:slug', Component: ResearchPostPage },
  { path: '/threatintel/ransomware-live', Component: RansomwareLive },
  { path: '/threatintel/cyberpulse', Component: CyberPulse },
  { path: '/threatintel/infra/ai-honeypot', Component: AiHoneypotObservatory },
  { path: '/threatintel/infra/ai-llm-intel', Component: AiLlmIntel },
  { path: '/threatintel/threat-actor-monitor', Component: ThreatActorMonitor },
  { path: '/threatintel/alerts', Component: AlertFeed },
  { path: '/threatintel/vera', Component: VeraChat },
  { path: '/threatintel/infostealer/:slug', Component: InfostealerDetail },
  { path: '/dfir/owasp', Component: Owasp },
  { path: '/dfir/prompt-injection', Component: PromptInjection },
  { path: '/dfir/pi-taxonomy', Component: PiTaxonomy },
  { path: '/dfir/mcp-audit', Component: McpAudit },
  { path: '/dfir/kill-chain', Component: KillChain },
  { path: '/dfir/diamond', Component: Diamond },
  { path: '/dfir/osint-mapper', Component: OsintMapper },
  { path: '/dfir/lolbins', Component: Lolbins },
  { path: '/dfir/lots', Component: Lots },
  { path: '/dfir/malapi', Component: Malapi },
  { path: '/dfir/car', Component: Car },
  { path: '/dfir/capec', Component: Capec },
  { path: '/dfir/hijacklibs', Component: Hijacklibs },
  { path: '/dfir/veris', Component: Veris },
  { path: '/dfir/engage', Component: Engage },
  { path: '/dfir/ct-monitor', Component: CtMonitor },
  { path: '/dfir/stealer-parser', Component: StealerParser },
  { path: '/dfir/threat-graph', Component: ThreatGraph },
  { path: '/dfir/attack-navigator', Component: AttackNavigator },
  { path: '/dfir/ir-playbooks', Component: IrPlaybooks },
  { path: '/dfir/phishops', Component: PhishOps },
  { path: '/dfir/phishbook', Component: PhishBook },
  { path: '/dfir/pivex', Component: Pivex },
  { path: '/dfir/crypto-tracer', Component: CryptoTracer },
  { path: '/dfir/email-defense', Component: EmailDefense },
  { path: '/dfir/dmarc-analyzer', Component: DmarcAnalyzer },
  { path: '/dfir/nhi', Component: Nhi },
  { path: '/dfir/powershell-deobf', Component: PowershellDeobf },
  { path: '/dfir/powershell-analyzer', Component: PowershellAnalyzer },
  { path: '/dfir/agent-history', Component: InvestigationHistory },
  { path: '/dfir/agent-suite', Component: AgentSuite },
  { path: '/dfir/detection-chokepoints', Component: DetectionChokepointsHub },
  { path: '/dfir/subdomain-takeover', Component: SubdomainTakeover },
  { path: '/dfir/grc', Component: Grc },
  { path: '/dfir/dlp-scan', Component: DlpScan },
  { path: '/dfir/data-classification', Component: DataClassification },
  { path: '/dfir/privacy-hub', Component: PrivacyHub },
  { path: '/dfir/username-investigator', Component: UsernameInvestigator },
  { path: '/dfir/domain-investigator', Component: DomainInvestigator },
  { path: '/dfir/passive-dns', Component: PassiveDns },
  { path: '/dfir/malware-analyzer', Component: MalwareAnalyzer },
  { path: '/dfir/notebooks', Component: Notebooks },
  { path: '/dfir/ioc-investigate', Component: IocInvestigate },
  { path: '/dfir/copilot', Component: DfirCopilotPage },
  { path: '/dfir/yara-workbench', Component: YaraWorkbench },
  { path: '/dfir/stix-workbench', Component: StixWorkbench },
  { path: '/dfir/wifi-investigation', Component: WifiInvestigation },
  { path: '/dfir/wayback', Component: Wayback },
  { path: '/dfir/log-parser', Component: LogParser },
  { path: '/dfir/socmint', Component: Socmint },
  { path: '/dfir/infostealer-intel', Component: InfostealerIntel },
  { path: '/dfir/timestamp', Component: TimestampConverter },
  { path: '/dfir/hash-calc', Component: HashCalculator },
  { path: '/dfir/brand-impersonation', Component: BrandImpersonation },
  { path: '/dfir/plist-protobuf', Component: PlistProtobuf },
  { path: '/dfir/pcap-triage', Component: PcapTriage },
  { path: '/dfir/registry-hive', Component: RegistryHive },
  { path: '/dfir/evtx', Component: EvtxParser },
  { path: '/dfir/sqlite', Component: SqliteExplorer },
  { path: '/dfir/ios-backup', Component: IosBackupExplorer },
  { path: '/dfir/apk-analyzer', Component: ApkAnalyzer },
  { path: '/dfir/web-log', Component: WebLogAnalyzer },
  { path: '/dfir/prefetch', Component: PrefetchAnalyzer },
  { path: '/dfir/ai-suite', Component: AiSuite },
  { path: '/dfir/dnscope', Component: Dnscope },
  { path: '/dfir/tracerules', Component: Tracerules },

  { path: '/dfir/catalog', Component: DfirCatalog },
  { path: '/dfir/eml', Component: EmlExtractor },
  { path: '/dfir/url-risk', Component: UrlRisk },
  { path: '/dfir/email-rep', Component: EmailReputation },
  { path: '/dfir/email-osnit', Component: EmailOsnit },
  { path: '/threatintel/catalog', Component: ThreatIntelCatalog },
  { path: '/threatintel/about', Component: ThreatIntelAbout },
  { path: '/threatintel', Component: ThreatIntelHome },
  { path: '/threatintel/assessments/:id', Component: AssessmentDetail },
  { path: '/threatintel/mcp-search', Component: McpSearch },

  { path: '/threatintel/live-center', Component: LiveCenter },
  { path: '/threatintel/live-feed', Component: LiveFeed },
  { path: '/threatintel/cve/:id', Component: CveDetail },
  { path: '/threatintel/cves/:cveId', Component: CveDetail },
  // ── Threat Intel: direct page URLs (auto-added by audit) ──
  { path: '/threatintel/actors/hub', Component: ActorHub },
  { path: '/threatintel/actors/attribution', Component: Attribution },
  { path: '/threatintel/darkweb/watch', Component: DarkWeb },
  { path: '/threatintel/darkweb/markets', Component: DarknetMarketsTimeline },
  { path: '/threatintel/darkweb/darknetlist', Component: DarknetList },
  { path: '/threatintel/breach-hub', Component: BreachHub },
  { path: '/threatintel/darkweb/deepdark', Component: DeepDarkCTI },
  { path: '/threatintel/darkweb/crime', Component: CyberCrime },
  { path: '/threatintel/darkweb/infostealer', Component: Infostealer },
  { path: '/threatintel/darkweb/leaks', Component: SecretLeaks },

  { path: '/threatintel/ransomware-hub', Component: RansomwareHub },
  { path: '/threatintel/exposure', Component: ExposureCheck },
  { path: '/threatintel/ransomware-groups', Component: RansomwareGroups },
  { path: '/threatintel/ai-escape', Component: AiEscape },
  { path: '/threatintel/ai-security', Component: AiSecurityHub },
  { path: '/threatintel/ai-incidents', Component: AiIncidents },
  { path: '/threatintel/ai-security-matrix', Component: AiSecurityMatrix },
  { path: '/threatintel/ai-vulns', Component: AiVulns },
  { path: '/threatintel/ai-advisories', Component: AiAdvisories },
  { path: '/threatintel/darkweb/recon', Component: DarkWebRecon },
  { path: '/threatintel/darkweb/playbook', Component: DarkWebPlaybook },
  { path: '/threatintel/onion-watch', Component: OnionWatch },
  { path: '/threatintel/predictive/dashboard', Component: IntelDashboard },
  { path: '/threatintel/predictive/global-pulse', Component: GlobalPulse },
  { path: '/threatintel/predictive/threat-pulse', Component: ThreatPulse },
  { path: '/threatintel/predictive/certstream', Component: CertStreamLive },
  { path: '/threatintel/predictive/metrics', Component: Metrics },
  { path: '/threatintel/predictive/predictions', Component: Predictions },
  { path: '/threatintel/predictive/predictive', Component: PredictiveIntel },
  { path: '/threatintel/detection-wiki', Component: DetectionWiki },
  { path: '/threatintel/detections/detections', Component: Detections },
  { path: '/threatintel/detections/disarm', Component: DisarmFramework },
  { path: '/threatintel/detections/yara', Component: YaraPage },
  { path: '/threatintel/detections/signal', Component: ThreatSignalRss },
  { path: '/threatintel/phishing/phish', Component: PhishFeed },
  { path: '/threatintel/phishing/urls', Component: PhishingWordlists },
  { path: '/threatintel/phishing/scam', Component: ScamWatch },
  { path: '/threatintel/external/external', Component: ExternalResources },
  { path: '/threatintel/supply-chain', Component: SupplyChainHub },
  { path: '/threatintel/entity-graph', Component: EntityGraphPage },
  { path: '/threatintel/external/awesome', Component: AwesomeLists },
  { path: '/threatintel/feeds/catalog', Component: FeedCatalog },
  { path: '/threatintel/feeds/sources', Component: FeedSources },
  { path: '/threatintel/feeds/quality', Component: FeedQuality },
  { path: '/threatintel/feeds/scheduler', Component: FeedScheduler },
  { path: '/threatintel/feeds/threatcluster', Component: ThreatClusterFeeds },
  {
    path: '/threatintel/feeds/threatcluster/entities',
    Component: ThreatClusterEntities,
  },
  { path: '/threatintel/feeds/threaticon', Component: ThreaticonFeeds },
  { path: '/threatintel/feeds/dphish', Component: DphishFeeds },
  { path: '/threatintel/cairn', Component: Cairn },
  { path: '/threatintel/nova', Component: Nova },
  { path: '/threatintel/denali', Component: Denali },
  { path: '/threatintel/ai-playbook', Component: AiSecurityPlaybook },
  { path: '/threatintel/feeds/destroylist', Component: DestroylistFeeds },
  { path: '/threatintel/feeds/living-threat', Component: LivingThreatFeeds },
  { path: '/threatintel/feeds/malwareanalyzer', Component: MalwareAnalyzerFeeds },
  { path: '/threatintel/feeds/threatfeeds', Component: ThreatFeeds },
  { path: '/threatintel/feeds/mythreatintel', Component: MyThreatIntel },
  { path: '/threatintel/infra/cloud', Component: CloudThreatLandscape },
  { path: '/threatintel/infra/infra', Component: InfraIntel },
  { path: '/threatintel/infra/webamon', Component: Webamon },
  { path: '/threatintel/infra/domain', Component: DomainMonitor },
  { path: '/threatintel/iocs/live', Component: LiveIocs },
  { path: '/threatintel/iocs/enrichment', Component: IocEnrichment },
  { path: '/threatintel/iocs/feeds', Component: IocFeedsPage },
  { path: '/threatintel/iocs/entity', Component: EntityResolution },
  { path: '/threatintel/iocs/c2', Component: C2Tracker },
  { path: '/threatintel/iocs/map', Component: ThreatMap },
  { path: '/threatintel/iocs/correlation', Component: IocCorrelation },
  { path: '/threatintel/wiki/wiki', Component: Wiki },
  { path: '/threatintel/wiki/mitre', Component: MitreMatrix },
  { path: '/threatintel/wiki/f3ead', Component: F3ead },
  { path: '/threatintel/wiki/f2t2ea', Component: F2t2ea },
  { path: '/threatintel/wiki/ooda', Component: Ooda },
  { path: '/threatintel/wiki/threat-led-defence', Component: ThreatLedDefence },
  { path: '/threatintel/wiki/kill-chain-v2', Component: KillChainV2 },
  { path: '/threatintel/wiki/unified-kill-chain', Component: UnifiedKillChain },
  { path: '/threatintel/wiki/insider', Component: InsiderThreatMatrix },
  { path: '/threatintel/wiki/owasp', Component: OwaspAiLandscape },
  { path: '/threatintel/wiki/llm', Component: LlmThreatAtlas },
  { path: '/threatintel/malware/iocs', Component: MalwareIocs },
  { path: '/threatintel/malware/sandbox', Component: MalwareSandbox },

  { path: '/threatintel/malware/malpedia', Component: MalpediaPage },
  { path: '/threatintel/malware/maltrail', Component: MaltrailTrails },
  { path: '/threatintel/osint/framework', Component: OsintFramework },
  { path: '/threatintel/osint/cli', Component: OsintCliTools },
  { path: '/threatintel/osint/map', Component: OsintCountryMap },
  { path: '/threatintel/osint/toolbox', Component: CuratedToolbox },
  { path: '/threatintel/osint/certs', Component: CuratedCerts },
  { path: '/threatintel/osint/secops', Component: SecopsCatalog },
  { path: '/threatintel/osint/threat-actor-monitor', Component: ThreatActorMonitor },
  { path: '/threatintel/osint/directory', Component: OsintDirectory },
  { path: '/threatintel/cti-bookmarks', Component: CtiBookmarks },
  { path: '/threatintel/research-hub/redhunt-labs', Component: RedHuntLabsResearch },
  { path: '/threatintel/research-hub/reports', Component: Reports },
  { path: '/threatintel/research-hub/ai', Component: AIReportShowcase },
  { path: '/threatintel/research-hub/agentic', Component: AgenticReports },
  { path: '/threatintel/research-hub/writeups', Component: Writeups },
  { path: '/threatintel/research-hub/signal', Component: ResearchSignal },
  { path: '/threatintel/research-hub/redhunt', Component: RedHuntInsights },
  { path: '/threatintel/research-hub/volexity', Component: VolexityThreatIntel },
  { path: '/threatintel/research-hub/post', Component: ResearchPostPage },
  { path: '/threatintel/research-hub/attack-flow', Component: AttackFlowLibrary },
  { path: '/threatintel/flowviz', Component: FlowViz },
  { path: '/dfir/procedure-extract', Component: ProcedureExtract },
  { path: '/threatintel/research-hub/knowledge', Component: KnowledgeGraph },
  { path: '/threatintel/research-hub/ach', Component: ACH },
  { path: '/threatintel/social/firehose', Component: SocialFirehose },
  { path: '/threatintel/social/news', Component: TechAiNews },
  { path: '/threatintel/social/crypto-scam', Component: CryptoScamFeed },
  { path: '/threatintel/tools/copilot', Component: Copilot },
  // McpToolsExplorer merged into /threatintel/mcp-search (redirect in REDIRECTS).
  { path: '/threatintel/tools/stix-hub', Component: StixHub },
  // CisaKevCatalog route moved to redirect below
  { path: '/threatintel/tools/directory', Component: ToolsDirectory },
  { path: '/threatintel/tools/darknet-intel', Component: DarknetIntel },
  { path: '/threatintel/tools/tg-intel-search', Component: TgIntelSearch },
  { path: '/threatintel/tools/socradar-tools', Component: SocradarTools },
  { path: '/threatintel/tools/unified-search', Component: UnifiedSearch },
  { path: '/threatintel/tools/stix-bundles', Component: ThreatLandscapeStix },
  { path: '/threatintel/cves/cves', Component: CveIntel },
  { path: '/threatintel/cves/advisories', Component: GithubAdvisories },
  { path: '/threatintel/cves/resources', Component: CveResourcesCatalog },
  { path: '/dfir/pgp-tool', Component: PgpTool },
  { path: '/dfir/one-time-secret', Component: OneTimeSecret },
  { path: '/dfir/blocklists', Component: Blocklists },
  { path: '/dfir/frameworks/tid-cmm', Component: TidCmm },
  { path: '/dfir/frameworks/utiom', Component: Utiom },
  // ── 24 Gap Features ──────────────────────────────────────────────
  { path: '/dfir/export-hub', Component: ExportHub },
  { path: '/dfir/report-hub', Component: ReportHub },
  { path: '/admin', Component: AdminApp },
  { path: '/admin/analytics', Component: AdminAnalyticsDashboard },
  { path: '/anarchy', Component: Anarchy },
  { path: '/anarchy/c/:id', Component: Anarchy },
  { path: '/radar', Component: RadarHome },
  { path: '/radar/scan/:id', Component: RadarScanResults },
  { path: '/argus', Component: ArgusPage },
];

/** Legacy / renamed paths preserved as redirects so in-flight links don't 404. */
const REDIRECTS: ReadonlyArray<{ path: string; to: string; preserveQuery?: boolean }> = [
  // Old MCP explorer URL → merged MCP Search page.
  { path: '/threatintel/tools/mcp', to: '/threatintel/mcp-search' },
  { path: '/dfir/tools/:group', to: '/dfir/catalog' },
  { path: '/dfir/fleet-map', to: '/dfir/catalog' },
  { path: '/dfir/wordpress-sim', to: '/dfir/catalog' },
  { path: '/dfir/rhysida-intrusion', to: '/dfir/catalog' },
  { path: '/dfir/vs', to: '/dfir/catalog' },
  { path: '/dfir/tor-gateway', to: '/dfir/catalog' },
  { path: '/threatintel/malware/packages', to: '/threatintel/supply-chain?tab=feed' },
  { path: '/dfir/host', to: '/dfir/asset-intel' },
  // ── Hub merge redirects ──
  { path: '/dfir/decode', to: '/dfir/codec' },
  { path: '/dfir/encoder', to: '/dfir/codec' },
  { path: '/dfir/iam-analyzer', to: '/dfir/iam-hub' },
  { path: '/dfir/gcp-iam', to: '/dfir/iam-hub' },
  { path: '/dfir/azure-rbac', to: '/dfir/iam-hub' },
  { path: '/dfir/k8s-rbac', to: '/dfir/iam-hub' },
  { path: '/dfir/agent', to: '/dfir/agent-suite' },
  { path: '/dfir/agent-enrich', to: '/dfir/agent-suite' },
  { path: '/dfir/agent-map', to: '/dfir/agent-suite' },
  { path: '/agent', to: '/dfir/agent-suite' },
  { path: '/osint', to: '/dfir' },
  { path: '/threat-intel', to: '/threatintel' },
  { path: '/dfir/reverse-image', to: '/dfir/image-intel' },
  { path: '/dfir/image-fingerprint', to: '/dfir/image-intel' },
  { path: '/dfir/screenshot-intel', to: '/dfir/image-intel' },
  { path: '/dfir/phone-osint', to: '/dfir/phone-hub' },
  { path: '/dfir/phone-intel', to: '/dfir/phone-hub' },
  { path: '/dfir/sec-headers', to: '/dfir/sec-headers-live' },
  { path: '/dfir/takeover', to: '/dfir/subdomain-takeover' },
  { path: '/dfir/privacy', to: '/dfir/privacy-hub' },
  { path: '/threatintel/social/x-firehose', to: '/threatintel/social/x-hub' },
  { path: '/threatintel/social/x-live', to: '/threatintel/social/x-hub' },
  { path: '/threatintel/social/x-watch', to: '/threatintel/social/x-hub' },
  { path: '/threatintel/tools/stix', to: '/threatintel/tools/stix-hub' },
  { path: '/threatintel/tools/stix-ip-export', to: '/threatintel/tools/stix-hub' },
  { path: '/threatintel/darkweb/ransom-report', to: '/threatintel/ransomware-hub' },
  { path: '/threatintel/darkweb/ransom-activity', to: '/threatintel/ransomware-hub?tab=activity' },
  { path: '/threatintel/darkweb/ransom-map', to: '/threatintel/ransomware-hub' },
  { path: '/threatintel/darkweb/ransomwhere', to: '/threatintel/ransomware-hub' },
  { path: '/threatintel/tools/investigations', to: '/threatintel/investigation-suite' },
  { path: '/threatintel/tools/watches', to: '/threatintel/investigation-suite' },
  { path: '/threatintel/tools/workspaces', to: '/threatintel/investigation-suite' },
  { path: '/threatintel/ti-dashboard', to: '/threatintel/dashboard-hub' },
  { path: '/threatintel/cti-dashboard', to: '/threatintel/dashboard-hub' },
  { path: '/threatintel/dashboard', to: '/threatintel/dashboard-hub' },

  { path: '/dfir/sigma-convert', to: '/dfir/rule-converter' },
  { path: '/dfir/discord-watch', to: '/threatintel/catalog?cat=social' },
  { path: '/dfir/industry-news', to: '/threatintel/catalog?cat=social' },
  { path: '/difr', to: '/dfir' },
  { path: '/osint-tools', to: '/threatintel/osint/cli' },
  { path: '/threatnexus/', to: '/argus' },
  { path: '/threatnexus', to: '/argus' },

  // ── Duplicate routes (same component) - collapsed 2026-06 ─────
  // Aliases of tab-hubs (DomainInvestigator, IocInvestigate, etc.) point
  // at the same component so they're not separate pages - redirect them.
  { path: '/dfir/dork-builder', to: '/dfir/google-dorks' },
  { path: '/dfir/report-parser', to: '/dfir/report-hub' },
  { path: '/dfir/report-analyzer', to: '/dfir/report-hub' },
  { path: '/dfir/report-composer', to: '/dfir/report-hub' },
  { path: '/dfir/mobile-sqlite', to: '/dfir/sqlite' },
  // ── ThreatIntel hub merges ──
  { path: '/threatintel/actors/directory', to: '/threatintel/actors/hub?tab=directory' },
  { path: '/threatintel/actors/timeline', to: '/threatintel/actors/hub?tab=timeline' },
  { path: '/threatintel/actors/dna', to: '/threatintel/actors/hub?tab=dna' },
  { path: '/threatintel/actors/usernames', to: '/threatintel/actors/hub?tab=usernames' },
  { path: '/threatintel/actors/profiles', to: '/threatintel/actors/hub?tab=profiles' },
  { path: '/threatintel/actors/graph', to: '/threatintel/actors/hub?tab=graph' },
  { path: '/threatintel/darkweb/forums', to: '/threatintel/breach-hub?tab=forums' },
  { path: '/threatintel/darkweb/disclosures', to: '/threatintel/breach-hub?tab=disclosures' },
  { path: '/threatintel/darkweb/breach-watch', to: '/threatintel/breach-hub?tab=watch' },
  { path: '/threatintel/tools/kev-catalog', to: '/threatintel/cves?tab=kev' },
  { path: '/threatintel/external/supply', to: '/threatintel/supply-chain' },
  { path: '/threatintel/depx', to: '/threatintel/supply-chain' },
  { path: '/threatintel/malware/supply-chain', to: '/threatintel/supply-chain' },
  { path: '/dfir/crypto-trace', to: '/dfir/crypto-tracer', preserveQuery: true }, // ?address=<btc|evm> pre-seeds Tracer
  { path: '/dfir/tracer', to: '/dfir/crypto-tracer' },
  { path: '/dfir/tracepulse', to: '/dfir/crypto-tracer' },
  { path: '/dfir/quicktrace', to: '/dfir/crypto-tracer' },
  { path: '/dfir/insight-ai', to: '/dfir/ai-suite' },
  { path: '/dfir/querycraft-ai', to: '/dfir/ai-suite' },
  { path: '/dfir/chrono-ai', to: '/dfir/ai-suite' },
  { path: '/dfir/malbrief-ai', to: '/dfir/ai-suite' },
  { path: '/dfir/verdikt-ai', to: '/dfir/ai-suite' },
  { path: '/dfir/username', to: '/dfir/username-investigator' },
  { path: '/dfir/username-osint', to: '/dfir/username-investigator' },
  { path: '/dfir/identity-lookup', to: '/dfir/username-investigator' },
  { path: '/winreg', to: '/dfir/winreg' },
  { path: '/sigbase', to: '/dfir/sigbase' },
  { path: '/traceix', to: '/dfir/traceix' },
  { path: '/nhi-scan', to: '/dfir/nhi-scan' },
  { path: '/nhi', to: '/dfir/nhi-scan' },
  { path: '/whoxy', to: '/dfir/whoxy' },
  { path: '/threatintel/research-hub/campaign-gen', to: '/threatintel/campaigns/generator' },
  { path: '/threatintel/tools/graph', to: '/threatintel/actors/hub' },
  // Tab-hub aliases - same component, different default tab
  { path: '/dfir/domain', to: '/dfir/domain-investigator' },
  { path: '/dfir/domain-lookup', to: '/dfir/domain-investigator', preserveQuery: true }, // ?domain=<d> seeds DNS tab
  { path: '/dfir/asn-lookup', to: '/dfir/asn', preserveQuery: true }, // ?asn=/?q= pre-fill the lookup
  { path: '/dfir/breach-check', to: '/dfir/breach', preserveQuery: true }, // ?email= handled by Breach deep-link fallback
  { path: '/dfir/file-analyze', to: '/dfir/ioc-investigate', preserveQuery: true }, // hash lookups land on IOC Investigator
  { path: '/dfir/domain-rep', to: '/dfir/domain-investigator' },
  { path: '/dfir/webcheck', to: '/dfir/domain-investigator' },
  { path: '/dfir/web-scan', to: '/dfir/domain-investigator' },
  { path: '/dfir/full-spectrum', to: '/dfir/domain-investigator' },
  { path: '/dfir/ioc-check', to: '/dfir/ioc-investigate', preserveQuery: true },
  { path: '/dfir/ioc-pivot', to: '/dfir/ioc-investigate', preserveQuery: true },
  { path: '/dfir/threat-hunt', to: '/dfir/ioc-investigate', preserveQuery: true },
  { path: '/dfir/malware-scan', to: '/dfir/malware-analyzer' },
  { path: '/dfir/sample-scan', to: '/dfir/malware-analyzer' },
  { path: '/dfir/malware-capabilities', to: '/dfir/malware-analyzer' },
  { path: '/dfir/sandbox', to: '/dfir/malware-analyzer' },
  { path: '/dfir/yara', to: '/dfir/yara-workbench' },
  { path: '/dfir/rule-playground', to: '/dfir/yara-workbench' },
  { path: '/dfir/stix', to: '/dfir/stix-workbench' },
  { path: '/dfir/stix-builder', to: '/dfir/stix-workbench' },
  { path: '/dfir/taxii', to: '/dfir/stix-workbench' },
  { path: '/dfir/report-ingest', to: '/dfir/stix-workbench' },

  // ── Social Hub ──────────────────────────────────────────────────
  { path: '/threatintel/cybersec', to: '/threatintel/telegram' },
  { path: '/threatintel/breach', to: '/threatintel/telegram' },
  { path: '/threatintel/cyber-crime', to: '/threatintel/telegram' },
  { path: '/threatintel/telegram-watch', to: '/threatintel/telegram' },
  { path: '/threatintel/telegram-settings', to: '/threatintel/telegram' },
  { path: '/threatintel/telegram-leaks', to: '/threatintel/telegram' },
  { path: '/threatintel/telegram-leaks/channels', to: '/threatintel/telegram' },
  { path: '/threatintel/telegram-leaks/stats', to: '/threatintel/telegram' },
  { path: '/threatintel/telegram-monitor', to: '/threatintel/telegram' },
  { path: '/threatintel/telegram-iocs', to: '/threatintel/telegram' },
  { path: '/threatintel/tech-ai-news', to: '/threatintel/catalog?cat=social' },
  { path: '/threatintel/x-watch', to: '/threatintel/social/x-hub' },
  { path: '/threatintel/x-live', to: '/threatintel/social/x-hub' },
  { path: '/threatintel/x', to: '/threatintel/social/x-hub' },
  { path: '/threatintel/reddit', to: '/threatintel/social/firehose' },
  { path: '/threatintel/scam-watch', to: '/threatintel/social/crypto-scam' },
  { path: '/threatintel/crypto-scams', to: '/threatintel/social/crypto-scam' },
  { path: '/threatintel/mythreatintel', to: '/threatintel/catalog?cat=social' },
  { path: '/threatintel/status', to: '/threatintel/catalog?cat=social' },

  // ── Telegram subsumed by TelegramHub ─────
  { path: '/threatintel/social/telegram-leaks', to: '/threatintel/telegram' },
  { path: '/threatintel/social/telegram-stats', to: '/threatintel/telegram' },
  { path: '/threatintel/social/telegram-channels', to: '/threatintel/telegram' },
  { path: '/threatintel/social/telegram-settings', to: '/threatintel/telegram' },
  // ── SocialFirehose subsumes Reddit and X ─────
  { path: '/threatintel/social/reddit', to: '/threatintel/social/firehose' },
  { path: '/threatintel/social/scraped-intel', to: '/threatintel/social/firehose' },
  // ── SourceHealth subsumes Feed Status + Reliability ─────
  { path: '/threatintel/feeds/status', to: '/threatintel/source-health' },
  { path: '/threatintel/feeds/reliability', to: '/threatintel/source-health' },
  // ── CveIntel subsumes K8s + Exploitable tabs ─────
  { path: '/threatintel/cves/k8s', to: '/threatintel/cves/cves' },
  { path: '/threatintel/cves/exploitable', to: '/threatintel/cves/cves' },
  { path: '/threatintel/cves/list', to: '/threatintel/cves/cves' },
  // The 24h digest is a tab on CveIntel, but it gets its own deep-linkable
  // path so it can be shared/bookmarked directly. `preserveQuery` is NOT set:
  // the tab is the content, not a filter on the list view.
  { path: '/threatintel/cves/digest', to: '/threatintel/cves/cves?tab=digest' },
  // ── Canonical 2-segment hub paths → real page (defensive - direct
  //    `to`/`href` from a component should use the real path; this
  //    redirect exists so external links, bookmarks, and copy-paste
  //    URLs to the short path still land on a real page, not a 404).
  { path: '/threatintel/cves', to: '/threatintel/cves/cves' },
  { path: '/threatintel/social', to: '/threatintel/social/firehose' },

  // ── Dark Web Hub ────────────────────────────────────────────────
  { path: '/threatintel/deepdarkcti', to: '/threatintel/darkweb/deepdark' },
  { path: '/threatintel/re-leaks', to: '/threatintel/darkweb/leaks' },
  { path: '/threatintel/ransomware-map', to: '/threatintel/darkweb/ransom-map' },
  { path: '/threatintel/ransomware-activity', to: '/threatintel/ransomware-hub?tab=activity' },
  { path: '/threatintel/ransom-report', to: '/threatintel/darkweb/ransom-report' },
  { path: '/threatintel/negotiations', to: '/threatintel/darkweb/ransom-activity?tab=negotiations' },
  { path: '/threatintel/ransomwhere', to: '/threatintel/darkweb/ransomwhere' },
  { path: '/threatintel/breach-forums', to: '/threatintel/breach-hub' },
  { path: '/threatintel/darkweb-tools', to: '/threatintel/darkweb/watch' },
  // ── Duplicate standalone pages → hub tabs ────────────────────────
  { path: '/threatintel/ai-honeypot-observatory', to: '/threatintel/infra/ai-honeypot' },
  { path: '/threatintel/knowledge-graph', to: '/threatintel/research-hub/knowledge' },

  // ── IOC Hub ─────────────────────────────────────────────────────
  { path: '/threatintel/c2-tracker', to: '/threatintel/iocs/c2' },
  { path: '/threatintel/iocs/soc', to: '/threatintel/soc-dashboard' }, // tab of SocDashboard
  { path: '/threatintel/soc-iocs', to: '/threatintel/iocs/live' },
  { path: '/threatintel/live-iocs', to: '/threatintel/iocs/live' },
  { path: '/threatintel/ioc-enrichment', to: '/threatintel/iocs/enrichment' },
  { path: '/threatintel/entity-resolution', to: '/threatintel/iocs/entity' },
  { path: '/threatintel/threat-map', to: '/threatintel/iocs/map' },
  { path: '/threatintel/threat-feeds', to: '/threatintel/feeds/threatfeeds' },
  { path: '/threatintel/aggregated-feeds', to: '/threatintel/feeds/threatfeeds' },
  { path: '/threatintel/correlation', to: '/threatintel/catalog?cat=iocs' },
  // ── Retired tool pages ────────────────────────────────────────────────
  // Each of these was dropped as duplicate/low-value; the category hub it
  // lived under still exists, so the URL redirects there rather than 404ing
  // (these are indexed in sitemap.xml and prerendered).
  { path: '/threatintel/investigation-suite', to: '/threatintel/catalog?cat=campaigns' },
  { path: '/threatintel/tools/actionable-iocs', to: '/threatintel/catalog?cat=iocs' },
  { path: '/threatintel/tools/settings', to: '/threatintel/catalog?cat=tools' },
  { path: '/threatintel/tools/misp', to: '/threatintel/actors/hub' },
  { path: '/threatintel/predictive/observe', to: '/threatintel/catalog?cat=predictive' },
  { path: '/threatintel/predictive/pir', to: '/threatintel/catalog?cat=predictive' },
  { path: '/threatintel/dashboard-hub', to: '/threatintel/catalog?cat=monitoring-estate' },
  { path: '/threatintel/predictive/analyze', to: '/threatintel/catalog?cat=predictive' },
  { path: '/threatintel/predictive/assessments', to: '/threatintel/catalog?cat=predictive' },
  { path: '/threatintel/estate', to: '/threatintel/catalog?cat=monitoring-estate' },
  // Campaigns / actor / IOC pages removed in the same pass.
  { path: '/threatintel/campaigns/cross', to: '/threatintel/briefings' },
  { path: '/threatintel/cross-campaign', to: '/threatintel/briefings' },
  { path: '/threatintel/campaigns/reference', to: '/threatintel/briefings' },
  { path: '/threatintel/campaigns/active', to: '/threatintel/catalog?cat=campaigns' },
  { path: '/threatintel/campaigns/lifecycle', to: '/threatintel/catalog?cat=campaigns' },
  { path: '/threatintel/campaigns/generator', to: '/threatintel/catalog?cat=campaigns' },
  { path: '/threatintel/apt-tracker', to: '/threatintel/actors/hub' },
  { path: '/threatintel/most-wanted', to: '/threatintel/actors/hub' },
  { path: '/threatintel/extremists', to: '/threatintel/actors/hub' },
  { path: '/threatintel/predators', to: '/threatintel/actors/hub' },
  { path: '/threatintel/apt-actors', to: '/threatintel/actors/hub' },
  { path: '/threatintel/aptmap', to: '/threatintel/actors/hub' },
  { path: '/threatintel/iocs/cross', to: '/threatintel/catalog?cat=iocs' },
  { path: '/threatintel/iocs/observable', to: '/threatintel/catalog?cat=iocs' },
  { path: '/threatintel/iocs/aggregated', to: '/threatintel/feeds/sources' },
  { path: '/threatintel/malware/vault', to: '/threatintel/catalog?cat=malware' },
  { path: '/threatintel/social/x-hub', to: '/threatintel/catalog?cat=social' },
  { path: '/threatintel/darkweb/bitcoin', to: '/threatintel/catalog?cat=darkweb' },
  { path: '/threatintel/research-hub/research', to: '/threatintel/catalog?cat=research-hub' },
  { path: '/threatintel/research-hub/library', to: '/threatintel/catalog?cat=research-hub' },
  { path: '/threatintel/cross-correlate', to: '/threatintel/catalog?cat=iocs' },
  { path: '/threatintel/observable-db', to: '/threatintel/catalog?cat=iocs' },
  { path: '/threatintel/bitwire-blocklist', to: '/threatintel/feeds/threatfeeds' },
  { path: '/threatintel/certstream', to: '/threatintel/iocs/live' },
  { path: '/threatintel/domain-monitor', to: '/threatintel/catalog?cat=iocs' },
  { path: '/threatintel/facilities', to: '/threatintel/catalog?cat=iocs' },
  { path: '/threatintel/pulse', to: '/threatintel/catalog?cat=iocs' },
  { path: '/threatintel/ioc-feeds', to: '/threatintel/feeds/threatfeeds' },

  // ── Feed Hub ────────────────────────────────────────────────────
  { path: '/threatintel/feed-sources', to: '/threatintel/feeds/sources' },
  { path: '/threatintel/feed-quality', to: '/threatintel/feeds/quality' },
  { path: '/threatintel/feed-scheduler', to: '/threatintel/feeds/scheduler' },
  { path: '/threatintel/feed-catalog', to: '/threatintel/feeds/catalog' },
  { path: '/threatintel/collection-slo', to: '/threatintel/feeds/quality' },
  { path: '/threatintel/settings', to: '/threatintel/tools/settings' },

  // ── Predictive / Dashboard Hub ──────────────────────────────────
  { path: '/threatintel/predictions', to: '/threatintel/predictive/predictions' },
  { path: '/threatintel/analyze', to: '/threatintel/predictive/analyze' },
  { path: '/threatintel/observe', to: '/threatintel/predictive/observe' },
  { path: '/threatintel/intel-dashboard', to: '/threatintel/predictive/dashboard' },
  { path: '/threatintel/pir-dashboard', to: '/threatintel/predictive/dashboard' },
  { path: '/threatintel/soc-ransomware', to: '/threatintel/predictive/dashboard' },
  { path: '/threatintel/soc-vulns', to: '/threatintel/predictive/dashboard' },
  { path: '/threatintel/threat-landscape', to: '/threatintel/predictive/dashboard' },
  { path: '/threatintel/metrics', to: '/threatintel/predictive/dashboard' },
  { path: '/threatintel/predictive/analytics', to: '/threatintel/predictive/dashboard' },

  // ── Malware Hub ─────────────────────────────────────────────────
  { path: '/threatintel/malware-iocs', to: '/threatintel/malware/iocs' },
  { path: '/threatintel/malware-vault', to: '/threatintel/malware/vault' },
  { path: '/threatintel/malicious-packages', to: '/threatintel/supply-chain?tab=feed' },
  { path: '/threatintel/malpedia', to: '/threatintel/malware/malpedia' },
  { path: '/threatintel/maltrail', to: '/threatintel/malware/maltrail' },
  { path: '/threatintel/malware-sandbox', to: '/threatintel/malware/sandbox' },

  // ── Detection Hub ───────────────────────────────────────────────
  { path: '/threatintel/rules', to: '/threatintel/detections/detections' },
  { path: '/threatintel/detections', to: '/threatintel/detections/detections' },
  // ── Hub root redirects (catalog-filtered views are the canonical
  //    way to land on a hub; these 2-segment aliases exist for
  //    external links and the in-app components that point at them).
  { path: '/threatintel/actors', to: '/threatintel/catalog?cat=actors' },
  { path: '/threatintel/campaigns', to: '/threatintel/catalog?cat=campaigns' },
  { path: '/threatintel/iocs', to: '/threatintel/catalog?cat=iocs' },
  { path: '/threatintel/darkweb', to: '/threatintel/catalog?cat=darkweb' },
  { path: '/threatintel/feeds', to: '/threatintel/catalog?cat=feeds' },
  { path: '/threatintel/tools', to: '/threatintel/catalog?cat=tools' },
  { path: '/threatintel/wiki', to: '/threatintel/catalog?cat=wiki' },
  { path: '/threatintel/signal', to: '/threatintel/detections/signal' },
  { path: '/threatintel/threatsignal', to: '/threatintel/detections/signal' },
  { path: '/threatintel/detections/wiki', to: '/threatintel/detection-wiki' },
  { path: '/threatintel/yara', to: '/threatintel/detections/yara' },
  { path: '/threatintel/disarm', to: '/threatintel/detections/disarm' },

  // ── Knowledge Hub (wiki + frameworks) ──────────────────────────
  { path: '/threatintel/mitre', to: '/threatintel/wiki/mitre', preserveQuery: true }, // ?id=<technique> scopes the matrix
  { path: '/threatintel/owasp-ai-landscape', to: '/threatintel/wiki/owasp' },
  { path: '/threatintel/insider-threat-matrix', to: '/threatintel/wiki/insider' },
  { path: '/threatintel/f3ead', to: '/threatintel/wiki/f3ead' },
  { path: '/threatintel/f2t2ea', to: '/threatintel/wiki/f2t2ea' },
  { path: '/threatintel/ooda', to: '/threatintel/wiki/ooda' },
  { path: '/threatintel/kill-chain-v2', to: '/threatintel/wiki/kill-chain-v2' },
  { path: '/threatintel/unified-kill-chain', to: '/threatintel/wiki/unified-kill-chain' },
  { path: '/threatintel/llm-threat-atlas', to: '/threatintel/wiki/llm' },
  { path: '/threatintel/atlas', to: '/threatintel/catalog?cat=wiki' },

  // ── Tools Hub ───────────────────────────────────────────────────
  { path: '/threatintel/copilot', to: '/threatintel/tools/copilot' },
  { path: '/threatintel/copilot-chat', to: '/threatintel/tools/copilot' },
  { path: '/threatintel/misp-browser', to: '/threatintel/tools/misp' },
  { path: '/threatintel/investigations', to: '/threatintel/tools/investigations' },
  { path: '/threatintel/watches', to: '/threatintel/tools/watches' },
  { path: '/threatintel/workspaces', to: '/threatintel/tools/workspaces' },
  { path: '/threatintel/relationship-graph', to: '/threatintel/actors/hub' },
  { path: '/threatintel/search', to: '/threatintel/catalog?cat=tools' },
  { path: '/threatintel/campaign-generator', to: '/threatintel/catalog?cat=tools' },
  { path: '/threatintel/ach', to: '/threatintel/catalog?cat=tools' },
  { path: '/threatintel/stix-bundles', to: '/threatintel/tools/stix' },
  { path: '/threatintel/source-reliability', to: '/threatintel/catalog?cat=tools' },

  // ── External Hub ────────────────────────────────────────────────
  { path: '/threatintel/external-resources', to: '/threatintel/external/external' },
  { path: '/threatintel/awesome-lists', to: '/threatintel/external/awesome' },
  { path: '/threatintel/projectdiscovery', to: '/threatintel/catalog?cat=external' },

  // ── Research Hub ────────────────────────────────────────────────
  { path: '/threatintel/research', to: '/threatintel/research-hub/research' },
  { path: '/threatintel/redhunt-labs', to: '/threatintel/research-hub/redhunt' },
  { path: '/threatintel/redhunt-insights', to: '/threatintel/research-hub/redhunt' },
  { path: '/threatintel/ai-report', to: '/threatintel/research-hub/ai' },
  { path: '/threatintel/writeups', to: '/threatintel/research-hub/writeups' },
  { path: '/threatintel/reports', to: '/threatintel/research-hub/reports' },

  // ── OSINT Hub ───────────────────────────────────────────────────
  { path: '/threatintel/osint-framework', to: '/threatintel/osint/framework' },
  { path: '/threatintel/osint-map', to: '/threatintel/osint/map' },
  { path: '/threatintel/curated-toolbox', to: '/threatintel/osint/toolbox' },
  { path: '/threatintel/secops-tools', to: '/threatintel/osint/secops' },
  { path: '/threatintel/osint-cli-tools', to: '/threatintel/osint/cli' },
  { path: '/threatintel/cve-resources', to: '/threatintel/catalog?cat=cves' },
  { path: '/threatintel/cve-list', to: '/threatintel/cves/cves', preserveQuery: true }, // ?q=<cve> seeds CveList search
  // ── Actor Hub ──────────────────────────────────────────────────
  { path: '/threatintel/actor-kb', to: '/threatintel/catalog?cat=actors' },
  { path: '/threatintel/actors/kb', to: '/threatintel/actors/hub' }, // tab of ActorDirectory
  { path: '/threatintel/actors/catalog', to: '/threatintel/actors/hub?tab=catalog' },
  { path: '/threatintel/actor-dna', to: '/threatintel/catalog?cat=actors' },
  { path: '/threatintel/actor-timeline', to: '/threatintel/actors/hub', preserveQuery: true }, // ?actor=<slug> highlights the row
  { path: '/threatintel/actor-usernames', to: '/threatintel/actors/hub' },
  { path: '/threatintel/threat-actor-catalog', to: '/threatintel/catalog?cat=actors' },
  { path: '/threatintel/threat-actor-db', to: '/threatintel/catalog?cat=actors' },
  { path: '/threatintel/intelligence-gaps', to: '/threatintel/catalog?cat=actors' },

  // ── Campaign Hub ───────────────────────────────────────────────
  { path: '/threatintel/campaign-lifecycle', to: '/threatintel/campaigns/lifecycle' },
  { path: '/threatintel/attribution', to: '/threatintel/actors/attribution' },

  // ── Phishing Hub ────────────────────────────────────────────────
  { path: '/threatintel/phishing-wordlists', to: '/threatintel/phishing/urls' },

  // ── Assessments ─────────────────────────────────────────────────
  { path: '/threatintel/assessments', to: '/threatintel/predictive/assessments' },
  // ── Pre-existing drill routes (prerendered in scripts/prerender.mjs) ───
  { path: '/dfir/detection-lab', to: '/dfir/rule-converter' },
  { path: '/dfir/dashboard', to: '/dfir' },
  { path: '/dfir/atlas', to: '/threatintel/wiki/llm' },
  { path: '/threatintel/infostealer', to: '/threatintel/catalog?cat=malware' },
  { path: '/copilot', to: '/threatintel/tools/copilot' },
];

/**
 * Path prefix → the component its owning host renders at `/`.
 *
 * These are the SAME components the apex paths already use
 * (`/dfir` → DFIR, `/threatintel` → ThreatIntelHome, `/radar` → RadarHome,
 * `/argus` → ArgusPage), so a subdomain root and its apex path are guaranteed
 * to render identical content. Adding a host means adding one entry here plus
 * one in `TOOL_HOSTS_BY_PATH` and `vars.TOOLS_HOSTS`.
 *
 * Keyed by prefix rather than hostname so the lookup in `SurfaceHome` can
 * invert `TOOL_HOSTS_BY_PATH` directly and stay in sync automatically.
 */
const LANDING_BY_PREFIX: Readonly<Record<string, ComponentType>> = {
  '/dfir': DFIR,
  '/threatintel': ThreatIntelHome,
  '/radar': RadarHome,
  '/argus': ArgusPage,
  // Single-page hosts: their `/` is that one tool, not the parent area's
  // landing. These reuse the same components the apex paths render, so
  // `agent./` and `/dfir/agent-suite` stay identical.
  '/dfir/agent-suite': AgentSuite,
  '/threatintel/tools/copilot': Copilot,
  '/daily-briefs': DailyBriefs,
};

/**
 * `/` — the one route whose CONTENT differs by surface.
 *
 * Chrome (nav) is handled by PortfolioShell; this is the Home → ToolsHome
 * swap. It reads the surface from context so the prerenderer's explicit
 * value wins during SSR, and the hostname wins in the browser.
 */
function SurfaceHome() {
  const surface = useSurface();
  if (surface === 'portfolio') return <Home />;

  // During SSR there is no `window`, so the prerenderer resolves the host
  // itself: it renders `/` once per surface with an explicit `surface` prop,
  // and that pass falls through to ToolsHome below. In the browser the
  // hostname decides, which is what actually varies per host.
  const host = typeof window === 'undefined' ? '' : window.location.hostname.toLowerCase();
  const owned = Object.entries(TOOL_HOSTS_BY_PATH).find(([, toolHost]) => toolHost === host);
  if (!owned) return <ToolsHome />;

  const Landing = LANDING_BY_PREFIX[owned[0]];
  // These landings are `lazy()`, and `/` is an EAGER route (it renders
  // directly rather than through <LazyRoute>), so there is no Suspense
  // boundary above this point. Without one, React throws on the suspended
  // lazy component and the ErrorBoundary swallows the whole page — which is
  // why the tools hosts rendered empty until this was wrapped.
  return Landing ? (
    <Suspense fallback={<TabLoader />}>
      <Landing />
    </Suspense>
  ) : (
    <ToolsHome />
  );
}

export function AppContent({ surface }: { surface?: Surface } = {}) {
  const { isDark, toggleTheme } = useTheme();
  const location = useLocation();
  const navigationType = useNavigationType();

  // Which front door this render is for. Passed explicitly by the
  // prerenderer (SSR has no window → would always answer "portfolio");
  // resolved from location.hostname in the browser.
  const activeSurface: Surface = surface ?? currentSurface();

  // Tools nav is per-HOST, not per-surface. Every tools host serves the same
  // route table, so a single shared array meant `scout.` advertised
  // PANOPTICON's dropdown while rendering the recon scanner — nav and landing
  // disagreed about which product you were on. A host with no entry falls back
  // to the all-tools nav so nothing becomes unreachable.
  const activeNavLinks =
    activeSurface === 'portfolio'
      ? navLinks
      : (TOOLS_NAV_BY_HOST[typeof window === 'undefined' ? '' : window.location.hostname.toLowerCase()] ??
        toolsNavLinks);

  // /dfir/* and /threatintel/* are stand-alone web apps hosted next to the
  // portfolio. They get their own app-shell chrome and skip the portfolio
  // Header / Footer / background-gradient layer entirely. This is the
  // single most-important "feel" toggle on the site - sub-pages of those
  // two routes should not look like sub-pages of someone's portfolio.
  const appMode: 'dfir' | 'threatintel' | 'radar' | 'argus' | null = location.pathname.startsWith('/dfir')
    ? 'dfir'
    : location.pathname.startsWith('/argus')
      ? 'argus'
      : location.pathname.startsWith('/threatintel')
        ? 'threatintel'
        : location.pathname.startsWith('/radar')
          ? 'radar'
          : null;
  const isAppRoute = appMode !== null;

  // Hash-anchor scrolling + scroll-to-top on navigation.
  //
  // - With a hash: poll for the target element (rAF, ~1s cap) because lazy
  //   routes mount a frame or two after the location changes — a single
  //   getElementById at effect time misses and deep links like /page#section
  //   silently never scroll.
  // - Without: jump to top only on fresh navigations (PUSH/REPLACE). POP
  //   (browser Back/Forward) must leave scroll alone so the browser's own
  //   position restoration works instead of yanking the user to the top.
  useEffect(() => {
    if (location.hash) {
      const id = location.hash.substring(1);
      let frames = 0;
      let raf = 0;
      const tryScroll = () => {
        const element = document.getElementById(id);
        if (element) {
          element.scrollIntoView({ behavior: 'smooth' });
          return;
        }
        if (frames++ < 60) raf = requestAnimationFrame(tryScroll);
      };
      raf = requestAnimationFrame(tryScroll);
      return () => cancelAnimationFrame(raf);
    }
    if (navigationType !== 'POP') {
      window.scrollTo({ top: 0, behavior: 'smooth' });
    }
  }, [location.pathname, location.hash, navigationType]);

  const routes = useMemo(
    () => (
      <Routes>
        {ROUTES.map(({ path, Component, eager }) => (
          <Route
            key={path}
            path={path}
            element={
              eager ? (
                <Component />
              ) : (
                <LazyRoute>
                  <Component />
                </LazyRoute>
              )
            }
          />
        ))}
        {REDIRECTS.map(({ path, to, preserveQuery }) => (
          <Route
            key={path}
            path={path}
            element={preserveQuery ? <QueryRedirect to={to} /> : <Navigate to={to} replace />}
          />
        ))}
        <Route
          path="*"
          element={
            <LazyRoute>
              <NotFound />
            </LazyRoute>
          }
        />
      </Routes>
    ),
    []
  );

  // ─── App-route render path (DFIR + ThreatIntel as stand-alone apps) ───
  // Keeps the same body bg + gradient overlay + noise texture as the
  // portfolio so the dark theme matches; swaps Header/Footer for AppShell.
  if (isAppRoute && appMode) {
    return (
      <>
        <StructuredData personalInfo={personalInfo} stats={stats} />
        <BackgroundLayer isDark={isDark} />
        <CommandPaletteGate />
        <McpProvider>
          <AppShell mode={appMode} isDark={isDark} onToggleTheme={toggleTheme}>
            {routes}
          </AppShell>
        </McpProvider>
        <div id="aria-live-region" aria-live="polite" aria-atomic="true" className="sr-only" />
      </>
    );
  }

  // ─── Portfolio render path ────────────────────────────────────────────
  return (
    <SurfaceContext.Provider value={activeSurface}>
      <PortfolioShell isDark={isDark} toggleTheme={toggleTheme} navLinks={activeNavLinks} personalInfo={personalInfo}>
        {routes}
      </PortfolioShell>
    </SurfaceContext.Provider>
  );
}

function PortfolioShell({
  isDark,
  toggleTheme,
  navLinks,
  personalInfo,
  children,
}: {
  isDark: boolean;
  toggleTheme: () => void;
  navLinks: import('./core/entities').NavLink[];
  personalInfo: import('./core/entities').PersonalInfo;
  children: React.ReactNode;
}) {
  const { progress, showBackToTop, scrollToTop } = useScrollProgress();

  return (
    <>
      <StructuredData personalInfo={personalInfo} stats={stats} />
      <SkipToContent />
      <BackgroundLayer isDark={isDark} />

      <ScrollProgress progress={progress} />
      <Header isDark={isDark} onToggleTheme={toggleTheme} navLinks={navLinks} />
      <CommandPaletteGate />

      <main id="main-content" tabIndex={-1}>
        <Layout>{children}</Layout>
      </main>

      <Footer personalInfo={personalInfo} />
      <BackToTop visible={showBackToTop} onClick={scrollToTop} />

      <div id="aria-live-region" aria-live="polite" aria-atomic="true" className="sr-only" />
    </>
  );
}

function App() {
  return (
    <BrowserRouter>
      {/* AuthProvider is intentionally NOT mounted: nothing consumes
          useAuth(), and mounting it fired an unconditional /api/v1/auth/me
          round-trip on every page load whose result was never read. */}
      <FeaturesProvider>
        <AppContent />
      </FeaturesProvider>
    </BrowserRouter>
  );
}

export default App;
