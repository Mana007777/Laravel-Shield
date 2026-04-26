<?php

namespace YourName\LaravelShield\Results;

enum Severity: int
{
    case CRITICAL = 100;
    case HIGH = 80;
    case MEDIUM = 50;
    case LOW = 20;
    case INFO = 0;

    public function label(): string
    {
        return match ($this) {
            self::CRITICAL => 'CRITICAL',
            self::HIGH => 'HIGH',
            self::MEDIUM => 'MEDIUM',
            self::LOW => 'LOW',
            self::INFO => 'INFO',
        };
    }

    public static function fromString(string $s): self
    {
        return match (strtolower($s)) {
            'critical' => self::CRITICAL,
            'high' => self::HIGH,
            'medium' => self::MEDIUM,
            'low' => self::LOW,
            'info' => self::INFO,
            default => self::INFO,
        };
    }

    public function atLeast(self $min): bool
    {
        return $this->value >= $min->value;
    }
}
