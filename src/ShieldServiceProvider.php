<?php

namespace Marlla3x\LaravelShield;

use Marlla3x\LaravelShield\Commands\AddIgnoreCommand;
use Marlla3x\LaravelShield\Commands\ScanCommand;
use Illuminate\Support\ServiceProvider;

class ShieldServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__.'/../config/shield.php', 'shield');
        $this->app->singleton(ScanCommandRunner::class, function () {
            return new ScanCommandRunner();
        });
    }

    public function boot(): void
    {
        if ($this->app->runningInConsole()) {
            $this->commands([
                ScanCommand::class,
                AddIgnoreCommand::class,
            ]);
        }
        $this->publishes([__DIR__.'/../config/shield.php' => config_path('shield.php')], 'shield-config');
    }
}
