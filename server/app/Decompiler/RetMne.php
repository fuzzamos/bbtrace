<?php

namespace App\Decompiler;

use Exception;

class RetMne extends BaseMnemonic
{
    public function process($state)
    {
        $operands = $this->operands;

        if (count($operands)) {
            if ($operands[0] instanceof ImmOpnd) {
                $state->esp += $operands[0]->imm;
            }
        }

        return $state;
    }

    public function toString($options = [])
    {
        $operands = $this->operands;

        $s = "return";
        if (count($operands)) {
            if ($operands[0] instanceof ImmOpnd) {
                $s .= sprintf(" then pop(%s)", $operands[0]);
            } else {
                throw new Exception();
            }
        }

        return $s;
    }
}
