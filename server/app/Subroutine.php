<?php

namespace App;

use Illuminate\Database\Eloquent\Model;

class Subroutine extends Model
{
    public $timestamps = false;
    public $incrementing = false;

    protected $guarded = [];

    public function module()
    {
        return $this->belongsTo(Module::class);
    }

    public function blocks()
    {
        return $this->hasMany(Block::class);
    }
}

