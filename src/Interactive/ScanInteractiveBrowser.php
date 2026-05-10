<?php

namespace Marlla3x\LaravelShield\Interactive;

use Marlla3x\LaravelShield\Results\Issue;
use Marlla3x\LaravelShield\Version;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Terminal;

class ScanInteractiveBrowser
{
    /**
     * @param list<Issue> $issues
     */
    public function run(array $issues, string $projectRoot, OutputInterface $out): void
    {
        if ($issues === []) {
            $out->writeln('<info>No findings to browse.</info>');
            return;
        }
        $terminal = new Terminal();
        $height = max(10, $terminal->getHeight() - 3);
        $idx = 0;
        $expanded = false;
        $stdin = fopen('php://stdin', 'r');
        if ($stdin === false) {
            $out->writeln('<error>stdin not available.</error>');
            return;
        }
        stream_set_blocking($stdin, true);
        if (function_exists('shell_exec') && PHP_OS_FAMILY !== 'Windows') {
            @shell_exec('stty -icanon -echo min 1 time 0 < /dev/tty 2>/dev/null');
        }
        try {
            while (true) {
                $this->render($out, $issues, $idx, $expanded, $height);
                $ch = $this->readKey($stdin);
                if ($ch === null || $ch === '') {
                    break;
                }
                if ($ch === "\x03") {
                    break;
                }
                if ($ch === 'q' || $ch === 'Q') {
                    break;
                }
                if ($ch === 'j' || $ch === "\e[B") {
                    $idx = min(count($issues) - 1, $idx + 1);
                    $expanded = false;
                } elseif ($ch === 'k' || $ch === "\e[A") {
                    $idx = max(0, $idx - 1);
                    $expanded = false;
                } elseif ($ch === "\n" || $ch === "\r") {
                    $expanded = !$expanded;
                } elseif ($ch === 'f' || $ch === 'F') {
                    $this->markFalsePositive($issues[$idx], $projectRoot, $out);
                } elseif ($ch === 'x' || $ch === 'X') {
                    $this->suppressInSource($issues[$idx], $out);
                } elseif ($ch === 's' || $ch === 'S') {
                    $this->saveJson($issues, $projectRoot, $out);
                }
            }
        } finally {
            if (function_exists('shell_exec') && PHP_OS_FAMILY !== 'Windows') {
                @shell_exec('stty sane < /dev/tty 2>/dev/null');
            }
            fclose($stdin);
        }
    }

    /**
     * @param list<Issue> $issues
     */
    private function render(OutputInterface $out, array $issues, int $idx, bool $expanded, int $height): void
    {
        $out->write("\e[H\e[J");
        $total = count($issues);
        $i = $issues[$idx];
        $out->writeln('<info>Laravel Shield interactive</info>  Finding '.($idx + 1).'/'.$total);
        $out->writeln(sprintf(
            '<comment>%s</> %s:%d  [%s] %s',
            $i->severity->label(),
            $i->file,
            $i->line,
            $i->scanner,
            $i->title
        ));
        $out->writeln('');
        if ($expanded) {
            $out->writeln('<fg=gray>Description:</> '.$i->description);
            $out->writeln('<fg=gray>Risk:</> '.$i->risk);
            $out->writeln('<info>Fix:</> '.$i->recommendation);
            $out->writeln('');
            $ctx = $this->snippet($i->file, $i->line);
            $out->writeln('<fg=gray>Context:</>');
            foreach ($ctx as $ln) {
                $out->writeln($ln);
            }
        } else {
            $out->writeln('<fg=gray>Press Enter to expand (file, snippet, risk, fix hint).</>');
        }
        $out->writeln('');
        $start = max(0, $idx - (int) floor($height / 2));
        $slice = array_slice($issues, $start, $height);
        foreach ($slice as $j => $item) {
            $k = $start + $j;
            $mark = $k === $idx ? '>' : ' ';
            $line = sprintf(
                '%s %s %s:%d %s',
                $mark,
                $item->severity->label(),
                basename($item->file),
                $item->line,
                (function_exists('mb_substr') ? mb_substr($item->title, 0, 60) : substr($item->title, 0, 60))
            );
            $out->writeln($k === $idx ? '<options=bold>'.$line.'</>' : $line);
        }
        $out->writeln('');
        $out->writeln(
            '<fg=gray>Finding '.($idx + 1).'/'.$total.' | ↑↓ Navigate | Enter Expand | f False-positive | x Suppress | s Save JSON | q Quit</>'
        );
    }

    /**
     * Read a single logical key (including ANSI arrow sequences).
     *
     * @param resource $stdin
     */
    private function readKey($stdin): ?string
    {
        $c = fread($stdin, 1);
        if ($c === false || $c === '') {
            return null;
        }
        if ($c !== "\e") {
            return $c;
        }
        $b = fread($stdin, 1);
        if ($b === false || $b === '') {
            return "\e";
        }
        if ($b !== '[') {
            return "\e".$b;
        }
        $seq = '';
        for ($i = 0; $i < 8; $i++) {
            $ch = fread($stdin, 1);
            if ($ch === false || $ch === '') {
                break;
            }
            $seq .= $ch;
            if ($ch !== '' && ctype_alpha($ch)) {
                break;
            }
        }

        return "\e[".$seq;
    }

    /**
     * @return list<string>
     */
    private function snippet(string $file, int $line): array
    {
        if (!is_file($file)) {
            return ['(file not readable)'];
        }
        $lines = file($file, FILE_IGNORE_NEW_LINES);
        if ($lines === false) {
            return ['(could not read file)'];
        }
        $out = [];
        $start = max(0, $line - 2);
        $end = min(count($lines), $line + 1);
        for ($n = $start; $n < $end; $n++) {
            $prefix = ($n + 1 === $line) ? '>> ' : '   ';
            $out[] = $prefix.($n + 1).' | '.($lines[$n] ?? '');
        }

        return $out;
    }

    private function markFalsePositive(Issue $issue, string $projectRoot, OutputInterface $out): void
    {
        $path = rtrim($projectRoot, '/\\').'/.shieldignore';
        $rel = str_replace($projectRoot, '', $issue->file);
        $rel = ltrim(str_replace('\\', '/', $rel), '/');
        $line = '# false-positive '.$rel.':'.$issue->line.' '.$issue->scanner;
        @file_put_contents($path, $line."\n", FILE_APPEND);
        $out->writeln('<info>Appended to .shieldignore</info>');
    }

    private function suppressInSource(Issue $issue, OutputInterface $out): void
    {
        if (!is_file($issue->file) || $issue->line < 1) {
            $out->writeln('<error>Cannot suppress: invalid file.</error>');
            return;
        }
        $lines = file($issue->file, FILE_IGNORE_NEW_LINES);
        if ($lines === false) {
            return;
        }
        $i = $issue->line - 1;
        $comment = '// shield:ignore: '.$issue->scanner;
        if (str_ends_with($issue->file, '.blade.php')) {
            $comment = '{{-- shield:ignore: '.$issue->scanner.' --}}';
        }
        array_splice($lines, $i, 0, [$comment]);
        $body = implode("\n", $lines);
        file_put_contents($issue->file, $body."\n");
        $out->writeln('<info>Suppression comment inserted above line '.$issue->line.'</info>');
    }

    /**
     * @param list<Issue> $issues
     */
    private function saveJson(array $issues, string $projectRoot, OutputInterface $out): void
    {
        $name = rtrim($projectRoot, '/\\').'/shield-interactive-'.gmdate('Ymd-His').'.json';
        $payload = [
            'version' => Version::VERSION,
            'exported_at' => gmdate('c'),
            'issues' => array_map(static fn (Issue $i) => $i->toArray(), $issues),
        ];
        @file_put_contents($name, json_encode($payload, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR));
        $out->writeln('<info>Saved '.$name.'</info>');
    }
}
