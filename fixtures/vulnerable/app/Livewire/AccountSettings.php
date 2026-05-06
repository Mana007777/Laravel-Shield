<?php

namespace App\Livewire;

use App\Models\User;
use Livewire\Component;

class AccountSettings extends Component
{
    public string $name = '';
    public string $bio = '';

    public function save(): void
    {
        User::query()->where('id', auth()->id())->update([
            'name' => $this->name,
            'bio' => $this->bio,
        ]);
    }

    public function render()
    {
        return view('livewire.account-settings');
    }
}
