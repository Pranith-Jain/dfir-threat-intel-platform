/**
 * Legacy raw-palette baseline for the `no-raw-colors` ESLint rule.
 *
 * Generated, not hand-maintained. Regenerate with:
 *
 *     node scripts/update-raw-colors-baseline.mjs
 *
 * ## Why this exists
 *
 * `no-raw-colors` (added in 3d66d0e0c) is correct about what it reports: the
 * rule's own test suite passes. But it also flags ~1,800 pre-existing usages
 * across 203 files, and CI gates on `--max-warnings 0`, so enabling it repo-
 * wide fails every push.
 *
 * ## Why a baseline rather than turning the rule off
 *
 * Turning the rule off entirely would also stop it catching NEW raw colours,
 * which is the actual value. This list scopes the waiver to the files that
 * already carry the debt, so the rule stays live everywhere else - including
 * any file added after this baseline was generated.
 *
 * ## Why the residue is not bulk-fixable
 *
 * The rule auto-fixes the cases where the mapping is provably a rename: the
 * light half of the pair exactly equals the token's light value, so nothing
 * moves. Those are applied (`npm run lint:baseline -- --fix`, see below) and
 * the list shrinks as files clear.
 *
 * What remains is reported but deliberately NOT auto-fixed, because the
 * rewrite would change rendering rather than spelling:
 *
 *  - `dark:bg-white/10` and friends. White at 10% LIFTS a navy card;
 *    `--surface-100` is near-black in dark mode, so the token form DARKENS
 *    it. Same class name, opposite effect.
 *  - `text-white` with no saturated fill behind it. White on a neutral
 *    surface is a contrast bug; renaming it to a reactive ink would hide that
 *    instead of surfacing it.
 *  - Steps with no token at all (`slate-950`, `border-slate-700`).
 *
 * Each entry should leave the list as its file is cleaned up.
 */
export const RAW_COLORS_BASELINE = [
  "src/components/AppShell.tsx",
  "src/components/CopyToClipboard.tsx",
  "src/components/DataPageLayout.tsx",
  "src/components/ErrorBoundary.tsx",
  "src/components/FeedbackWidget.tsx",
  "src/components/Footer.tsx",
  "src/components/Header.tsx",
  "src/components/MobileSidebarDrawer.tsx",
  "src/components/SkipToContent.tsx",
  "src/components/StatBar.tsx",
  "src/components/dfir/IntodnsPanel.tsx",
  "src/components/dfir/ReportView.tsx",
  "src/components/dfir/report-view-helpers.ts",
  "src/components/intel/AiSummaryCard.tsx",
  "src/components/sections/Contact.tsx",
  "src/components/sections/Projects.tsx",
  "src/components/sections/Toolkits.tsx",
  "src/components/threatintel/BulkIocInput.tsx",
  "src/components/threatintel/FeedSummaryPanel.tsx",
  "src/components/threatintel/ThreatAnalysisPanel.tsx",
  "src/components/threatintel/XClaimsPanel.tsx",
  "src/components/threatintel/cti/CtiGlobe.tsx",
  "src/components/threatintel/soc/SocCharts.tsx",
  "src/pages/Cloak.tsx",
  "src/pages/CloudReference.tsx",
  "src/pages/DFIR.tsx",
  "src/pages/DailyBriefs.tsx",
  "src/pages/DfirRef.tsx",
  "src/pages/HuntHypotheses.tsx",
  "src/pages/McpCatalog.tsx",
  "src/pages/NotFound.tsx",
  "src/pages/Pqc.tsx",
  "src/pages/SiemLibrary.tsx",
  "src/pages/SigBase.tsx",
  "src/pages/WinReg.tsx",
  "src/pages/admin/AdminApp.tsx",
  "src/pages/admin/AnalyticsDashboard.tsx",
  "src/pages/admin/AnalyticsTab.tsx",
  "src/pages/admin/ApiKeysTab.tsx",
  "src/pages/argus/views/GlobeView.tsx",
  "src/pages/dfir/AgentInvestigator.tsx",
  "src/pages/dfir/AgentMap.tsx",
  "src/pages/dfir/AttackNavigator.tsx",
  "src/pages/dfir/Catalog.tsx",
  "src/pages/dfir/CveLookup.tsx",
  "src/pages/dfir/DarkWeb.tsx",
  "src/pages/dfir/DetectionChokepointsHub.tsx",
  "src/pages/dfir/Diamond.tsx",
  "src/pages/dfir/DiamondModelSection.tsx",
  "src/pages/dfir/GrcEvidence.tsx",
  "src/pages/dfir/InfostealerIntel.tsx",
  "src/pages/dfir/IocPivot.tsx",
  "src/pages/dfir/IrPlaybooks.tsx",
  "src/pages/dfir/MitreMatrix.tsx",
  "src/pages/dfir/Notebooks.tsx",
  "src/pages/dfir/PhishBook.tsx",
  "src/pages/dfir/PhoneOsintNew.tsx",
  "src/pages/dfir/ReportAnalyzer.tsx",
  "src/pages/dfir/ThreatFeeds.tsx",
  "src/pages/dfir/UrlRisk.tsx",
  "src/pages/dfir/WikiArticle.tsx",
  "src/pages/dfir/ZeroTrustAiAgents.tsx",
  "src/pages/threatintel/AIReportShowcase.tsx",
  "src/pages/threatintel/AiHoneypotObservatory.tsx",
  "src/pages/threatintel/AssessmentDetail.tsx",
  "src/pages/threatintel/BreachForums.tsx",
  "src/pages/threatintel/Catalog.tsx",
  "src/pages/threatintel/CertInAdvisories.tsx",
  "src/pages/threatintel/CisaKevCatalog.tsx",
  "src/pages/threatintel/Copilot.tsx",
  "src/pages/threatintel/CveDetail.tsx",
  "src/pages/threatintel/CyberPulse.tsx",
  "src/pages/threatintel/DarkWebPlaybook.tsx",
  "src/pages/threatintel/DarkWebRecon.tsx",
  "src/pages/threatintel/DarknetList.tsx",
  "src/pages/threatintel/Detections.tsx",
  "src/pages/threatintel/Dphish.tsx",
  "src/pages/threatintel/EntityGraphPage.tsx",
  "src/pages/threatintel/ExploitableCves.tsx",
  "src/pages/threatintel/GithubAdvisories.tsx",
  "src/pages/threatintel/GlobalPulse.tsx",
  "src/pages/threatintel/Home.tsx",
  "src/pages/threatintel/Infostealer.tsx",
  "src/pages/threatintel/LiveFeed.tsx",
  "src/pages/threatintel/LiveIocs.tsx",
  "src/pages/threatintel/MalwareIocs.tsx",
  "src/pages/threatintel/OsintCountryMap.tsx",
  "src/pages/threatintel/PhishFeed.tsx",
  "src/pages/threatintel/RansomwareGroups.tsx",
  "src/pages/threatintel/RansomwareMap.tsx",
  "src/pages/threatintel/RedHuntInsights.tsx",
  "src/pages/threatintel/SupplyChainFeed.tsx",
  "src/pages/threatintel/TelegramDiscoveredChannels.tsx",
  "src/pages/threatintel/TelegramHub.tsx",
  "src/pages/threatintel/TgIntelSearch.tsx",
  "src/pages/threatintel/ThreatMonInfostealer.tsx",
  "src/pages/threatintel/ThreatPulse.tsx",
  "src/pages/threatintel/UnifiedSearch.tsx",
  "src/pages/threatintel/VeraChat.tsx"
];
