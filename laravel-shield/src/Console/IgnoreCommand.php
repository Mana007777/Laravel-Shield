<?php

namespace YourName\LaravelShield\Console;

use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;

#[AsCommand(name: 'ignore', description: 'Insert a // shield:ignore comment before a line (suppression)')]
class IgnoreCommand extends Command
{
    protected function configure(): void
    {
        $this->addArgument('file', InputArgument::REQUIRED, 'Path to a PHP/Blade file');
        $this->addArgument('line', InputArgument::REQUIRED, '1-based line number');
        $this->addArgument('scanner', InputArgument::OPTIONAL, 'Scanner key, or "all" (default: all)', 'all');
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $io = new SymfonyStyle($input, $output);
        $file = (string) $input->getArgument('file');
        if (!is_file($file)) {
            $io->error('File not found: '.$file);
            return Command::FAILURE;
        }
        $line = max(1, (int) $input->getArgument('line'));
        $scanner = (string) $input->getArgument('scanner');
        $c = (string) file_get_contents($file);
        $lines = preg_split("/\R/", $c) ?: [];
        $i = $line - 1;
        if ($i < 0 || $i >= count($lines)) {
            $io->error('Line is out of range');
            return Command::FAILURE;
        }
        $tag = '// shield:ignore: '.trim($scanner);
        if (str_contains($lines[$i] ?? '', 'shield:ignore')) {
            $io->warning('Line already has a shield:ignore tag');
            return Command::SUCCESS;
        }
        array_splice($lines, $i, 0, [$tag]);
        if (!file_put_contents($file, implode("\n", $lines).(str_ends_with($c, "\n") ? "\n" : ''))) {
            $io->error('Could not write file');
            return Command::FAILURE;
        }
        $io->success('Added suppression comment before line '.$line);
        return Command::SUCCESS;
    }
}
