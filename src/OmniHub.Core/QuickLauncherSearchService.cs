namespace OmniHub.Core;

public enum QuickCommandCategory
{
    Apps = 0,
    CloudVault = 1,
    AeonHandoff = 2,
    AiModelVault = 3,
    License = 4,
    Navigation = 5,
    System = 6
}

public sealed record QuickLauncherItem(
    string Id,
    string Title,
    string Subtitle,
    QuickCommandCategory Category,
    string BadgeText,
    string[] Keywords,
    Func<CancellationToken, Task>? ExecuteAsync = null);

public sealed record ScoredQuickLauncherItem(
    QuickLauncherItem Item,
    int Score);

/// <summary>
/// Raycast-style instant fuzzy search and command ranking engine for QuickLauncherWindow (Alt+Space).
/// Indexes static OmniHub commands, live .lfc snapshots, Aeon tabs, and AI model vault actions.
/// </summary>
public sealed class QuickLauncherSearchService
{
    public IReadOnlyList<ScoredQuickLauncherItem> Search(
        IEnumerable<QuickLauncherItem> catalog,
        string? query,
        int maxResults = 25)
    {
        ArgumentNullException.ThrowIfNull(catalog);

        var trimmed = query?.Trim() ?? "";
        if (trimmed.Length == 0)
        {
            return catalog
                .Take(maxResults)
                .Select((item, idx) => new ScoredQuickLauncherItem(item, 1000 - idx))
                .ToArray();
        }

        var tokens = trimmed.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        var results = new List<ScoredQuickLauncherItem>();

        foreach (var item in catalog)
        {
            int totalScore = 0;
            bool allMatched = true;

            foreach (var token in tokens)
            {
                int tokenScore = ScoreSingleToken(item, token);
                if (tokenScore <= 0)
                {
                    allMatched = false;
                    break;
                }
                totalScore += tokenScore;
            }

            if (allMatched && totalScore > 0)
            {
                results.Add(new ScoredQuickLauncherItem(item, totalScore));
            }
        }

        return results
            .OrderByDescending(r => r.Score)
            .ThenBy(r => r.Item.Category)
            .ThenBy(r => r.Item.Title, StringComparer.OrdinalIgnoreCase)
            .Take(maxResults)
            .ToArray();
    }

    public static int ScoreSingleToken(QuickLauncherItem item, string token)
    {
        if (string.IsNullOrWhiteSpace(token))
            return 1;

        int best = ScoreField(item.Title, token, weightMultiplier: 3);
        best = Math.Max(best, ScoreField(item.BadgeText, token, weightMultiplier: 2));
        best = Math.Max(best, ScoreField(item.Subtitle, token, weightMultiplier: 1));

        foreach (var kw in item.Keywords)
        {
            best = Math.Max(best, ScoreField(kw, token, weightMultiplier: 2));
        }

        return best;
    }

    private static int ScoreField(string? field, string queryToken, int weightMultiplier)
    {
        if (string.IsNullOrWhiteSpace(field))
            return 0;

        if (field.Equals(queryToken, StringComparison.OrdinalIgnoreCase))
            return 220 * weightMultiplier;

        if (field.StartsWith(queryToken, StringComparison.OrdinalIgnoreCase))
            return 180 * weightMultiplier;

        // Word-boundary prefix match (e.g., "lfc" in "Restore .lfc Snapshot")
        int idx = field.IndexOf(queryToken, StringComparison.OrdinalIgnoreCase);
        if (idx >= 0)
        {
            bool atBoundary = idx == 0 || !char.IsLetterOrDigit(field[idx - 1]);
            int posBonus = Math.Max(0, 25 - idx);
            return ((atBoundary ? 145 : 105) + posBonus) * weightMultiplier;
        }

        // Acronym / camelCase / subsequence fuzzy match
        int subseqScore = ComputeSubsequenceScore(field, queryToken);
        return subseqScore > 0 ? subseqScore * weightMultiplier : 0;
    }

    private static int ComputeSubsequenceScore(string text, string pattern)
    {
        int pIdx = 0;
        int consecutive = 0;
        int score = 0;

        for (int tIdx = 0; tIdx < text.Length && pIdx < pattern.Length; tIdx++)
        {
            if (char.ToLowerInvariant(text[tIdx]) == char.ToLowerInvariant(pattern[pIdx]))
            {
                bool boundary = tIdx == 0 || !char.IsLetterOrDigit(text[tIdx - 1]) || char.IsUpper(text[tIdx]);
                consecutive++;
                score += 12 + (consecutive * 6) + (boundary ? 10 : 0);
                pIdx++;
            }
            else
            {
                consecutive = 0;
            }
        }

        return pIdx == pattern.Length ? score : 0;
    }
}
