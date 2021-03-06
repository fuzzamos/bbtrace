<?php

/*
|--------------------------------------------------------------------------
| Application Routes
|--------------------------------------------------------------------------
|
| Here is where you can register all of the routes for an application.
| It is a breeze. Simply tell Lumen the URIs it should respond to
| and give it the Closure to call when that URI is requested.
|
*/

$app->group(['prefix' => 'api/v1'], function() use ($app)
{
    $app->get('blocks', 'BlockController@index');
    $app->get('block/{id}', 'BlockController@show');
    $app->get('subroutines', 'SubroutineController@index');
    $app->get('subroutine/{id}', 'SubroutineController@show');
    $app->get('graph', 'GraphController@index');
});

$app->get('/{path:.*}', function () use ($app) {
    $anal = $app->make(App\Services\BbAnalyzer::class);
    $env = [
        'name' => $anal->getName(),
        'version' => $app->version(),
    ];
    return view('greeting', ['env' => $env]);
});

