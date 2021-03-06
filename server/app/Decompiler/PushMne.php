<?php

namespace App\Decompiler;

use Exception;

class PushMne extends BaseMnemonic
{
    public function process($state)
    {
        $operands = $this->operands;

        // change esp first, then push
        $state->pushStack($operands[0]);

        return $state;
    }

    public function toString($options = [])
    {
        $operands = $this->operands;

        return sprintf("push(%s)", $operands[0]);
    }
}
