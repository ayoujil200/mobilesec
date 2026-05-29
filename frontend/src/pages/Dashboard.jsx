import React, { useEffect, useRef, useState } from 'react';
import { Link } from 'react-router-dom';
import apkScannerService from '../services/apkScanner';
import mlModelService from '../services/mlModel';
import Card from '../components/common/Card';
import Badge from '../components/common/Badge';
import LoadingSpinner from '../components/common/LoadingSpinner';
import { formatDate, getStatusColor } from '../utils/formatters';
import { useSettings } from '../context/SettingsContext';

const Dashboard = () => {
    const { t } = useSettings();
    const [stats, setStats] = useState(null);
    const [recentScans, setRecentScans] = useState([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState(null);
    const [trainingSource, setTrainingSource] = useState('mongodb');
    const [trainingRunning, setTrainingRunning] = useState(false);
    const [trainingStatus, setTrainingStatus] = useState('idle');
    const [trainingLogs, setTrainingLogs] = useState([
        'Ready. Choose a dataset source and start training to stream logs here.'
    ]);
    const [paperTables, setPaperTables] = useState(null);
    const [paperTablesLoading, setPaperTablesLoading] = useState(false);
    const [paperTablesError, setPaperTablesError] = useState(null);
    const eventSourceRef = useRef(null);
    const logEndRef = useRef(null);

    useEffect(() => {
        const fetchData = async () => {
            try {
                // Fetch stats and scans with error handling
                let statsData = null;
                let scansData = [];

                try {
                    const statsRes = await apkScannerService.getStats();
                    statsData = statsRes.data;
                } catch (statsErr) {
                    console.warn("Stats endpoint not available, using defaults:", statsErr.message);
                    // Use defaults if stats endpoint doesn't exist
                    statsData = { total_scans: 0, completed: 0, failed: 0 };
                }

                try {
                    const scansRes = await apkScannerService.getAllResults(5);
                    scansData = Array.isArray(scansRes.data) ? scansRes.data : scansRes.data.results || scansRes.data.items || [];
                } catch (scansErr) {
                    console.warn("Scans endpoint error:", scansErr.message);
                    scansData = [];
                }

                setStats(statsData);
                setRecentScans(scansData);
            } catch (err) {
                console.error("Dashboard error:", err);
                setError("Failed to load dashboard data");
            } finally {
                setLoading(false);
            }
        };

        fetchData();

        return () => {
            if (eventSourceRef.current) {
                eventSourceRef.current.close();
            }
        };
    }, []);

    useEffect(() => {
        logEndRef.current?.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    }, [trainingLogs]);

    const appendTrainingLog = (message) => {
        setTrainingLogs((current) => {
            const next = [...current, message];
            return next.slice(-500);
        });
    };

    const trainingSourceLabel = (source) => {
        if (source === 'controlled') return 'controlled trusted dataset';
        if (source === 'bootstrap') return 'development bootstrap';
        return 'MongoDB';
    };

    const startTraining = () => {
        if (trainingRunning) return;

        if (eventSourceRef.current) {
            eventSourceRef.current.close();
        }

        setTrainingLogs([
            `Starting ${trainingSourceLabel(trainingSource)} training...`
        ]);
        setTrainingStatus('running');
        setTrainingRunning(true);

        const eventSource = new EventSource(mlModelService.getTrainingStreamUrl(trainingSource));
        eventSourceRef.current = eventSource;

        eventSource.addEventListener('start', (event) => {
            appendTrainingLog(event.data);
        });

        eventSource.addEventListener('log', (event) => {
            appendTrainingLog(event.data);
        });

        eventSource.addEventListener('done', (event) => {
            appendTrainingLog(event.data);
            setTrainingStatus('done');
            setTrainingRunning(false);
            eventSource.close();
        });

        eventSource.addEventListener('error', (event) => {
            if (event.data) {
                appendTrainingLog(event.data);
                setTrainingStatus('failed');
            } else {
                appendTrainingLog('Training stream disconnected.');
                setTrainingStatus((status) => status === 'done' ? status : 'failed');
            }
            setTrainingRunning(false);
            eventSource.close();
        });

        eventSource.onerror = () => {
            appendTrainingLog('Training stream connection failed or closed.');
            setTrainingRunning(false);
            setTrainingStatus((status) => status === 'done' ? status : 'failed');
            eventSource.close();
        };
    };

    const generatePaperTables = async () => {
        setPaperTablesLoading(true);
        setPaperTablesError(null);
        try {
            const data = await mlModelService.getPaperTables();
            setPaperTables(data);
        } catch (err) {
            setPaperTablesError(err.response?.data?.detail || err.message || 'Failed to generate paper tables');
        } finally {
            setPaperTablesLoading(false);
        }
    };

    const copyLatex = async () => {
        if (!paperTables?.latex) return;
        const latex = Object.values(paperTables.latex).join('\n\n');
        await navigator.clipboard.writeText(latex);
    };

    const formatCell = (value) => {
        if (value === null || value === undefined) return 'N/A';
        if (typeof value === 'number') return Number.isInteger(value) ? value : value.toFixed(4);
        return String(value);
    };

    const renderSimpleTable = (rows) => {
        if (!rows || rows.length === 0) {
            return <p className="text-sm text-slate-500 dark:text-slate-400">No values available.</p>;
        }

        const columns = Object.keys(rows[0]);
        return (
            <div className="overflow-x-auto">
                <table className="w-full text-left text-sm">
                    <thead>
                        <tr className="border-b border-slate-200 dark:border-slate-700 text-slate-500 dark:text-slate-400">
                            {columns.map((column) => (
                                <th key={column} className="py-2 pr-4 whitespace-nowrap">{column}</th>
                            ))}
                        </tr>
                    </thead>
                    <tbody>
                        {rows.map((row, rowIndex) => (
                            <tr key={rowIndex} className="border-b border-slate-100 dark:border-slate-800">
                                {columns.map((column) => (
                                    <td key={column} className="py-2 pr-4 align-top text-slate-700 dark:text-slate-300">
                                        {formatCell(row[column])}
                                    </td>
                                ))}
                            </tr>
                        ))}
                    </tbody>
                </table>
            </div>
        );
    };

    const renderConfusionMatrix = (matrixInfo) => {
        const labels = matrixInfo?.labels || [];
        const matrix = matrixInfo?.matrix || [];
        if (!labels.length || !matrix.length) {
            return <p className="text-sm text-slate-500 dark:text-slate-400">No confusion matrix available.</p>;
        }

        const maxValue = Math.max(1, ...matrix.flat().map((value) => Number(value) || 0));

        return (
            <div className="overflow-x-auto">
                <table className="min-w-full border-collapse text-xs">
                    <thead>
                        <tr>
                            <th className="sticky left-0 z-10 bg-white dark:bg-slate-900 p-2 text-left font-semibold text-slate-500 dark:text-slate-400">
                                Actual \ Predicted
                            </th>
                            {labels.map((label) => (
                                <th
                                    key={label}
                                    className="p-2 text-center font-semibold text-slate-500 dark:text-slate-400 min-w-24 max-w-32"
                                    title={label}
                                >
                                    <span className="block truncate">{label}</span>
                                </th>
                            ))}
                        </tr>
                    </thead>
                    <tbody>
                        {matrix.map((row, rowIndex) => (
                            <tr key={labels[rowIndex] || rowIndex}>
                                <th
                                    className="sticky left-0 z-10 bg-white dark:bg-slate-900 p-2 text-left font-semibold text-slate-600 dark:text-slate-300 max-w-40"
                                    title={labels[rowIndex]}
                                >
                                    <span className="block truncate">{labels[rowIndex]}</span>
                                </th>
                                {row.map((value, columnIndex) => {
                                    const numericValue = Number(value) || 0;
                                    const intensity = numericValue / maxValue;
                                    const isCorrect = rowIndex === columnIndex;
                                    const background = isCorrect
                                        ? `rgba(22, 163, 74, ${0.12 + intensity * 0.55})`
                                        : `rgba(220, 38, 38, ${0.08 + intensity * 0.45})`;

                                    return (
                                        <td
                                            key={`${rowIndex}-${columnIndex}`}
                                            className="border border-slate-200 dark:border-slate-800 p-2 text-center font-mono text-slate-800 dark:text-slate-100"
                                            style={{ backgroundColor: background }}
                                            title={`Actual: ${labels[rowIndex]} | Predicted: ${labels[columnIndex]}`}
                                        >
                                            {numericValue}
                                        </td>
                                    );
                                })}
                            </tr>
                        ))}
                    </tbody>
                </table>
            </div>
        );
    };

    const renderConfusionMatrices = () => {
        const matrices = paperTables?.tables?.confusion_matrices || [];
        if (!matrices.length) {
            return <p className="text-sm text-slate-500 dark:text-slate-400">No confusion matrices available. Train/evaluate the model first.</p>;
        }

        return (
            <div className="space-y-4">
                {matrices.map((matrixInfo) => (
                    <div key={matrixInfo.model} className="rounded-lg border border-slate-200 dark:border-slate-800 overflow-hidden">
                        <div className="px-3 py-2 bg-slate-50 dark:bg-slate-950 border-b border-slate-200 dark:border-slate-800">
                            <h5 className="text-sm font-semibold text-slate-700 dark:text-slate-200">{matrixInfo.model}</h5>
                        </div>
                        <div className="p-3">
                            {renderConfusionMatrix(matrixInfo)}
                        </div>
                    </div>
                ))}
            </div>
        );
    };

    const renderLatexBlocks = () => {
        if (!paperTables?.latex) return null;

        const preferredOrder = [
            'table_3_lightgbm_prioritization',
            'table_5_tool_comparison',
            'table_6_benchmark_realworld',
        ];
        const entries = preferredOrder
            .filter((key) => paperTables.latex[key])
            .map((key) => [key, paperTables.latex[key]]);

        return (
            <div>
                <h4 className="font-semibold text-slate-800 dark:text-white mb-2">LaTeX Code</h4>
                <div className="space-y-3">
                    {entries.map(([key, latex]) => (
                        <div key={key} className="rounded-lg border border-slate-200 dark:border-slate-800 overflow-hidden">
                            <div className="flex items-center justify-between px-3 py-2 bg-slate-50 dark:bg-slate-950 border-b border-slate-200 dark:border-slate-800">
                                <span className="text-xs font-semibold uppercase text-slate-500 dark:text-slate-400">
                                    {key.replaceAll('_', ' ')}
                                </span>
                                <button
                                    type="button"
                                    onClick={() => navigator.clipboard.writeText(latex)}
                                    className="text-xs text-blue-600 dark:text-blue-400 hover:underline"
                                >
                                    Copy
                                </button>
                            </div>
                            <pre className="max-h-72 overflow-auto p-3 text-xs bg-white dark:bg-slate-900 text-slate-700 dark:text-slate-300 whitespace-pre-wrap font-mono">
                                {latex}
                            </pre>
                        </div>
                    ))}
                </div>
            </div>
        );
    };

    if (loading) return <LoadingSpinner />;
    if (error) return <div className="text-red-500 p-4">{error}</div>;

    return (
        <div className="space-y-6">
            <div className="flex justify-between items-center">
                <h2 className="text-2xl font-bold text-slate-800 dark:text-white">{t('dashboard')}</h2>
                <Link to="/upload" className="bg-green-600 hover:bg-green-700 text-white px-4 py-2 rounded-lg transition shadow-lg shadow-green-900/20">
                    + {t('new_scan')}
                </Link>
            </div>

            {/* Stats Cards */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                <Card className="border-l-4 border-l-blue-500">
                    <p className="text-slate-500 dark:text-slate-400 text-sm uppercase">{t('total_scans')}</p>
                    <p className="text-3xl font-bold text-slate-800 dark:text-white mt-1">{stats?.total_scans || 0}</p>
                </Card>
                <Card className="border-l-4 border-l-green-500">
                    <p className="text-slate-500 dark:text-slate-400 text-sm uppercase">{t('completed')}</p>
                    <p className="text-3xl font-bold text-slate-800 dark:text-white mt-1">{stats?.completed || stats?.completed_scans || 0}</p>
                </Card>
                <Card className="border-l-4 border-l-red-500">
                    <p className="text-slate-500 dark:text-slate-400 text-sm uppercase">{t('failed')}</p>
                    <p className="text-3xl font-bold text-slate-800 dark:text-white mt-1">{stats?.failed || stats?.failed_scans || 0}</p>
                </Card>
            </div>

            <Card
                title="ML Model Training"
                action={
                    <Badge type={trainingStatus === 'done' ? 'success' : trainingStatus === 'failed' ? 'danger' : trainingRunning ? 'warning' : 'default'}>
                        {trainingStatus}
                    </Badge>
                }
            >
                <div className="flex flex-col lg:flex-row lg:items-end gap-4">
                    <div className="flex-1">
                        <label htmlFor="training-source" className="block text-sm font-medium text-slate-600 dark:text-slate-300 mb-2">
                            Dataset source
                        </label>
                        <select
                            id="training-source"
                            value={trainingSource}
                            onChange={(event) => setTrainingSource(event.target.value)}
                            disabled={trainingRunning}
                            className="w-full bg-white dark:bg-slate-950 border border-slate-300 dark:border-slate-700 rounded-lg px-3 py-2 text-slate-800 dark:text-slate-100 focus:outline-none focus:ring-2 focus:ring-blue-500"
                        >
                            <option value="mongodb">MongoDB scan results</option>
                            <option value="controlled">Controlled trusted dataset</option>
                            <option value="bootstrap">Development bootstrap dataset</option>
                        </select>
                    </div>
                    <button
                        type="button"
                        onClick={startTraining}
                        disabled={trainingRunning}
                        className="bg-blue-600 hover:bg-blue-700 disabled:bg-slate-400 disabled:cursor-not-allowed text-white px-4 py-2 rounded-lg transition shadow-lg shadow-blue-900/20"
                    >
                        {trainingRunning ? 'Training...' : 'Train Model'}
                    </button>
                </div>

                <div className="mt-4 rounded-lg border border-slate-800 bg-slate-950 overflow-hidden">
                    <div className="flex items-center justify-between px-4 py-2 border-b border-slate-800 bg-slate-900">
                        <span className="text-xs font-semibold uppercase text-slate-300">Training console</span>
                        <button
                            type="button"
                            onClick={() => setTrainingLogs([])}
                            disabled={trainingRunning}
                            className="text-xs text-slate-400 hover:text-white disabled:opacity-50"
                        >
                            Clear
                        </button>
                    </div>
                    <pre className="h-72 overflow-y-auto p-4 text-xs leading-5 text-green-200 whitespace-pre-wrap font-mono">
                        {trainingLogs.map((line, index) => (
                            <div key={`${index}-${line.slice(0, 20)}`}>{line}</div>
                        ))}
                        <span ref={logEndRef} />
                    </pre>
                </div>
            </Card>

            <Card
                title="Paper Evaluation Tables"
                action={
                    <div className="flex gap-2">
                        <button
                            type="button"
                            onClick={generatePaperTables}
                            disabled={paperTablesLoading}
                            className="bg-slate-800 hover:bg-slate-900 disabled:bg-slate-400 disabled:cursor-not-allowed text-white px-3 py-2 rounded-lg text-sm transition"
                        >
                            {paperTablesLoading ? 'Generating...' : 'Generate Values'}
                        </button>
                        <button
                            type="button"
                            onClick={copyLatex}
                            disabled={!paperTables}
                            className="bg-green-600 hover:bg-green-700 disabled:bg-slate-400 disabled:cursor-not-allowed text-white px-3 py-2 rounded-lg text-sm transition"
                        >
                            Copy LaTeX
                        </button>
                    </div>
                }
            >
                {paperTablesError && (
                    <div className="mb-4 rounded-lg border border-red-500/30 bg-red-500/10 p-3 text-sm text-red-500">
                        {paperTablesError}
                    </div>
                )}

                {!paperTables ? (
                    <p className="text-sm text-slate-500 dark:text-slate-400">
                        Generate table values after running scans and training. Values that need ground truth or external tool imports are marked as N/A.
                    </p>
                ) : (
                    <div className="space-y-6">
                        {paperTables.warnings?.length > 0 && (
                            <div className="rounded-lg border border-yellow-500/30 bg-yellow-500/10 p-3">
                                <p className="text-sm font-semibold text-yellow-600 dark:text-yellow-400 mb-2">Warnings</p>
                                <ul className="list-disc pl-5 text-sm text-yellow-700 dark:text-yellow-300 space-y-1">
                                    {paperTables.warnings.map((warning, index) => (
                                        <li key={index}>{warning}</li>
                                    ))}
                                </ul>
                            </div>
                        )}

                        <div>
                            <h4 className="font-semibold text-slate-800 dark:text-white mb-2">Reviewer Checklist Status</h4>
                            {renderSimpleTable(paperTables.tables?.checklist_review)}
                        </div>

                        <div>
                            <h4 className="font-semibold text-slate-800 dark:text-white mb-2">Table 3: LightGBM Prioritization Model</h4>
                            {renderSimpleTable(paperTables.tables?.lightgbm_prioritization)}
                        </div>

                        <div>
                            <h4 className="font-semibold text-slate-800 dark:text-white mb-2">Table 5: Tool Comparison</h4>
                            {renderSimpleTable(paperTables.tables?.tool_comparison)}
                        </div>

                        <div>
                            <h4 className="font-semibold text-slate-800 dark:text-white mb-2">Table 6: Benchmark and Real-World APK Evaluation</h4>
                            {renderSimpleTable(paperTables.tables?.benchmark_realworld)}
                        </div>

                        <div>
                            <h4 className="font-semibold text-slate-800 dark:text-white mb-2">Supporting: Per-Category Detection</h4>
                            {renderSimpleTable(paperTables.tables?.category_detection)}
                        </div>

                        <div>
                            <h4 className="font-semibold text-slate-800 dark:text-white mb-2">Supporting: Evaluation Datasets</h4>
                            {renderSimpleTable(paperTables.tables?.evaluation_datasets)}
                        </div>

                        <div>
                            <h4 className="font-semibold text-slate-800 dark:text-white mb-2">Supporting: ML Baselines</h4>
                            {renderSimpleTable(paperTables.tables?.ml_results)}
                        </div>

                        <div>
                            <h4 className="font-semibold text-slate-800 dark:text-white mb-2">Supporting: Confusion Matrices</h4>
                            {renderConfusionMatrices()}
                        </div>

                        <div>
                            <h4 className="font-semibold text-slate-800 dark:text-white mb-2">Supporting: Feature Importance</h4>
                            {renderSimpleTable(paperTables.tables?.feature_importance)}
                        </div>

                        <div>
                            <h4 className="font-semibold text-slate-800 dark:text-white mb-2">Supporting: Model Configuration</h4>
                            {renderSimpleTable(paperTables.tables?.model_configuration)}
                        </div>

                        <div>
                            <h4 className="font-semibold text-slate-800 dark:text-white mb-2">Supporting: Label Provenance</h4>
                            {renderSimpleTable(paperTables.tables?.label_provenance)}
                        </div>

                        <div>
                            <h4 className="font-semibold text-slate-800 dark:text-white mb-2">Supporting: Concrete Misclassifications</h4>
                            {renderSimpleTable(paperTables.tables?.misclassification_examples)}
                        </div>

                        <div>
                            <h4 className="font-semibold text-slate-800 dark:text-white mb-2">Supporting: Failure Analysis</h4>
                            {renderSimpleTable(paperTables.tables?.failure_analysis)}
                        </div>

                        <div>
                            <h4 className="font-semibold text-slate-800 dark:text-white mb-2">Supporting: Quantitative Comparison</h4>
                            {renderSimpleTable(paperTables.tables?.quantitative_comparison)}
                        </div>

                        <div>
                            <h4 className="font-semibold text-slate-800 dark:text-white mb-2">Supporting: Weight Sensitivity</h4>
                            {renderSimpleTable(paperTables.tables?.weight_sensitivity)}
                        </div>

                        {renderLatexBlocks()}
                    </div>
                )}
            </Card>

            {/* Recent Scans Table */}
            <Card title={t('recent_scans')}>
                <div className="overflow-x-auto">
                    <table className="w-full text-left">
                        <thead>
                            <tr className="text-slate-500 dark:text-slate-400 border-b border-slate-200 dark:border-slate-700 text-sm">
                                <th className="pb-3 pl-2">{t('filename')}</th>
                                <th className="pb-3">{t('date')}</th>
                                <th className="pb-3">{t('status')}</th>
                                <th className="pb-3">{t('actions')}</th>
                            </tr>
                        </thead>
                        <tbody className="text-slate-600 dark:text-slate-300">
                            {recentScans.length === 0 ? (
                                <tr>
                                    <td colSpan="4" className="text-center py-4 text-slate-500">{t('no_scans')}</td>
                                </tr>
                            ) : (
                                recentScans.map((scan) => (
                                    <tr key={scan.scan_id} className="border-b border-slate-200 dark:border-slate-700/50 hover:bg-slate-50 dark:hover:bg-slate-800/50 transition">
                                        <td className="py-3 pl-2 font-medium text-slate-800 dark:text-white max-w-[200px]">
                                            <div className="truncate" title={scan.results?.apk_name || scan.results?.file_name || scan.app_name}>
                                                {scan.results?.apk_name || scan.results?.file_name || scan.app_name || 'Unknown.apk'}
                                            </div>
                                        </td>
                                        <td className="py-3 whitespace-nowrap">{formatDate(scan.created_at || scan.results?.scan_timestamp || scan.timestamp)}</td>
                                        <td className="py-3 whitespace-nowrap">
                                            <Badge type={getStatusColor(scan.status)}>{scan.status}</Badge>
                                        </td>
                                        <td className="py-3 whitespace-nowrap">
                                            <Link
                                                to={`/scans/${scan.scan_id}`}
                                                className="text-blue-500 hover:text-blue-700 dark:text-blue-400 dark:hover:text-blue-300 text-sm font-medium"
                                            >
                                                {t('view_details')}
                                            </Link>
                                        </td>
                                    </tr>
                                ))
                            )}
                        </tbody>
                    </table>
                </div>
            </Card>
        </div>
    );
};

export default Dashboard;
